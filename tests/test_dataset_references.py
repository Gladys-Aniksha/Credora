from __future__ import annotations

import pytest

from core import dataset_references as refs
from core.security import SecurityValidationError


@pytest.fixture
def project(tmp_path, monkeypatch):
    data = tmp_path / "data"
    for directory in (
        data / "processed",
        data / "sample_datasets",
        data / "uploads/7/datasets",
        data / "uploads/8/datasets",
        data / "sequence_test_kit/demo",
    ):
        directory.mkdir(parents=True)
    monkeypatch.setattr(refs, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(refs, "DATA_DIR", data)
    monkeypatch.setattr(refs, "PROCESSED_DATA_DIR", data / "processed")
    return tmp_path


@pytest.mark.parametrize(
    "path",
    [
        "data/uploads/7/datasets/train.csv",
        "data/processed/train.csv",
        "data/sample_datasets/train.csv",
    ],
)
def test_authorized_paths_are_copied_and_normalized(project, path):
    source = {"training_dataset_path": project / path, "class_labels": ["a", "b"]}
    result = refs.validate_training_dataset_references(source, owner_id=7)
    assert result["training_dataset_path"] == path
    assert source["training_dataset_path"] == project / path
    assert result["class_labels"] == ["a", "b"]


@pytest.mark.parametrize(
    "path",
    [
        "data/uploads/8/datasets/train.csv",
        "data/uploads/70/train.csv",
        "data/uploads/shared/train.csv",
        "data/raw/train.csv",
        "reports/train.csv",
        "data/unapproved_test_kit/demo/train.csv",
        "data/uploads/7/../8/datasets/train.csv",
        "../outside.csv",
    ],
)
def test_rejects_cross_owner_and_unapproved_project_paths(project, path):
    with pytest.raises(SecurityValidationError, match="own uploads"):
        refs.validate_training_dataset_references(
            {"training_dataset_path": path}, owner_id=7
        )


def test_owner_from_metadata_cannot_grant_access(project):
    with pytest.raises(SecurityValidationError):
        refs.validate_training_dataset_references(
            {
                "training_dataset_path": "data/uploads/8/datasets/train.csv",
                "owner_id": 8,
                "_owner_id": 8,
                "_trusted": True,
                "shared_dataset_roots": ["data/uploads"],
            },
            owner_id=7,
        )


def test_ownerless_calls_allow_only_approved_shared_data(project):
    result = refs.validate_training_dataset_references(
        {"training_dataset_path": "data/processed/train.csv"}, owner_id=None
    )
    assert result["training_dataset_path"] == "data/processed/train.csv"
    with pytest.raises(SecurityValidationError):
        refs.validate_training_dataset_references(
            {"training_dataset_path": "data/uploads/7/datasets/train.csv"},
            owner_id=None,
        )


@pytest.mark.parametrize("owner", [True, "7", 0, -1])
def test_invalid_owner_rejected(project, owner):
    with pytest.raises(SecurityValidationError):
        refs.validate_training_dataset_references({}, owner_id=owner)


def test_baseline_alias_promoted_and_both_aliases_checked(project):
    result = refs.validate_training_dataset_references(
        {"baseline_dataset_path": "data/processed/train.csv"}, owner_id=7
    )
    assert (
        result["training_dataset_path"]
        == result["baseline_dataset_path"]
        == "data/processed/train.csv"
    )
    with pytest.raises(SecurityValidationError):
        refs.validate_training_dataset_references(
            {
                "training_dataset_path": "data/processed/train.csv",
                "baseline_dataset_path": "data/uploads/8/datasets/train.csv",
            },
            owner_id=7,
        )
    with pytest.raises(SecurityValidationError, match="same dataset"):
        refs.validate_training_dataset_references(
            {
                "training_dataset_path": "data/processed/train.csv",
                "baseline_dataset_path": "data/processed/other.csv",
            },
            owner_id=7,
        )


@pytest.mark.parametrize(
    "value",
    [
        True,
        [],
        {},
        "bad\x00.csv",
        "data/processed/model.pkl",
        "data/processed/train.npz",
    ],
)
def test_malformed_reference_or_wrong_format_rejected(project, value):
    with pytest.raises(SecurityValidationError):
        refs.validate_training_dataset_references(
            {"training_dataset_path": value}, owner_id=7
        )


def test_sequence_requires_npz_and_missing_baseline_remains_valid(project):
    result = refs.validate_training_dataset_references(
        {
            "input_type": "sequence",
            "training_dataset_path": "data/processed/missing.npz",
        },
        owner_id=7,
    )
    assert result["training_dataset_path"] == "data/processed/missing.npz"
    assert (
        refs.validate_training_dataset_references(
            {"training_dataset_path": None, "baseline_dataset_path": ""}, owner_id=7
        )
        == {}
    )
    with pytest.raises(SecurityValidationError):
        refs.validate_training_dataset_references(
            {
                "input_type": "sequence",
                "training_dataset_path": "data/processed/train.csv",
            },
            owner_id=7,
        )


def test_directory_is_not_a_dataset(project):
    (project / "data/processed/fake.csv").mkdir()
    with pytest.raises(SecurityValidationError, match="regular"):
        refs.validate_training_dataset_references(
            {"training_dataset_path": "data/processed/fake.csv"}, owner_id=7
        )


@pytest.mark.parametrize(
    "directory", ["sequence_test_kit", "doh_onnx_test_kit", "trained_sequence_test_kit"]
)
def test_shipped_sequence_fixture_roots_approved_by_default(project, directory):
    reference = f"data/{directory}/demo/train.npz"
    result = refs.validate_training_dataset_references(
        {"input_type": "sequence", "training_dataset_path": reference}, owner_id=None
    )
    assert result["training_dataset_path"] == reference


def test_sequence_format_is_explicit_in_exported_model_metadata(project):
    result = refs.validate_training_dataset_references(
        {
            "input_type": "sequence",
            "training_dataset_path": "data/processed/train.npz",
        },
        owner_id=7,
    )
    assert result["training_dataset_path"] == "data/processed/train.npz"


def test_canonical_path_escape_rejected_without_symlink_privileges(
    project, monkeypatch
):
    candidate = project / "data/uploads/7/datasets/link.csv"
    victim = project / "data/uploads/8/datasets/private.csv"
    original_resolve = type(project).resolve

    def resolve(path, *args, **kwargs):
        if path == candidate:
            return victim
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(type(project), "resolve", resolve)
    with pytest.raises(SecurityValidationError, match="own uploads"):
        refs.validate_training_dataset_references(
            {"training_dataset_path": str(candidate)}, owner_id=7
        )


def test_sample_roots_must_be_explicit_operator_configuration(project):
    result = refs.validate_training_dataset_references(
        {"training_dataset_path": "data/sequence_test_kit/demo/train.csv"},
        owner_id=7,
        shared_dataset_roots=[project / "data/sequence_test_kit"],
    )
    assert result["training_dataset_path"] == "data/sequence_test_kit/demo/train.csv"
    for root in [
        project,
        project / "data",
        project / "data/uploads",
        project / "data/uploads/8",
    ]:
        with pytest.raises(SecurityValidationError, match="Shared dataset roots"):
            refs.validate_training_dataset_references(
                {}, owner_id=7, shared_dataset_roots=[root]
            )


def test_symlink_escape_and_owner_directory_redirect_rejected(project):
    victim = project / "data/uploads/8/datasets/private.csv"
    victim.write_text("secret\n1\n")
    link = project / "data/uploads/7/datasets/link.csv"
    try:
        link.symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable on this host.")
    with pytest.raises(SecurityValidationError):
        refs.validate_training_dataset_references(
            {"training_dataset_path": str(link)}, owner_id=7
        )
    shared_link = project / "data/processed/link.csv"
    shared_link.symlink_to(victim)
    with pytest.raises(SecurityValidationError):
        refs.validate_training_dataset_references(
            {"training_dataset_path": str(shared_link)}, owner_id=7
        )
    owner_link = project / "data/uploads/9"
    owner_link.symlink_to(victim.parents[1], target_is_directory=True)
    with pytest.raises(SecurityValidationError):
        refs.validate_training_dataset_references(
            {"training_dataset_path": "data/uploads/9/datasets/private.csv"}, owner_id=9
        )


def test_existing_tabular_consumers_accept_normalized_reference(project, monkeypatch):
    from modules.phase2_deep_trust.m10_dataset_leakage import leakage
    from modules.phase2_deep_trust.m11_privacy_risk import privacy

    monkeypatch.setattr(leakage, "DATA_DIR", project / "data")
    monkeypatch.setattr(privacy, "DATA_DIR", project / "data")
    expected = project / "data/uploads/7/datasets/train.csv"
    result = refs.validate_training_dataset_references(
        {"training_dataset_path": str(expected)}, owner_id=7
    )
    assert leakage._training_dataset_path(result) == expected
    assert privacy._training_dataset_path(result) == expected
