# Scope Cut and Security Hardening: Final Verification

Date: 2026-10-20. Local environment: Windows, Python 3.13.12, project `.venv`.
Comparison base: `c3ff9c2a0ae383f455934ef7db40fb8ede9ac938`.
This report concerns the four-phase scope-cut/security-hardening plan, not the
older feature-roadmap phase numbers used elsewhere in the repository.

## Verification Results

### Documentation and commit verification on 2026-10-26

The README now documents dashboard pages, retained assessment activity, matching
tabular/sequence fixture files, compatibility diagnostics, score-versus-release
semantics, captured-flow monitoring limits and CMD configuration troubleshooting.
The plain-language Word guide is included at `docs/Credora_Simple_Project_Guide.docx`.
Its document structure/content was checked; visual page rendering was unavailable
when it was authored, so pixel-level layout verification is not claimed.

A fresh focused run of upload UI, sequence data/backend, historical UI regressions,
PCAP adversarial, storage, access auditing, evidence and secure-upload tests
reported **215 passed, 1 failed, 1 teardown error, 2 warnings** in 212.56 seconds.
Both unsuccessful checks were timing assertions in the PCAP adversarial module:
a five-second subprocess deadline and its 60-second suite budget (93.83 seconds).
Running that entire module alone then passed **64 tests in 30.66 seconds** with
the same deadlines and unchanged parser/test code. This records the timing
sensitivity rather than silently removing a limit or calling the combined run green.

Fresh Ruff, mypy (98 source files), the Bandit high-severity profile and staged
whitespace checks passed. Local README documentation links resolved. Staged text
was checked for configured local secret values and none were found. The complete
regression suite was not rerun for this documentation/commit pass; the following
978-pass result remains the dated 2026-10-20 baseline, not a new full-suite result.

### Full hardening verification on 2026-10-20

Full regression run completed successfully: **978 passed, 5 skipped, 11 warnings**
in 597.88 seconds. The 11 focused historical-regression cases are included in
that full run.

| Check | Command or method | Result |
|---|---|---|
| Complete regression suite | `python -m pytest -q -rs` | Passed: 978 passed, 5 skipped |
| Ruff, existing CI profile | `ruff check --select E4,E7,E9,F --ignore E402 core modules scripts api dashboard tests` | Passed |
| mypy, existing CI profile | `mypy --ignore-missing-imports --explicit-package-bases --disable-error-code=arg-type --disable-error-code=var-annotated --disable-error-code=misc core modules scripts api` | Passed, 98 source files |
| Bandit, existing CI profile | `bandit -q -lll -r core modules scripts api dashboard` | Passed high-severity gate |
| Tracked whitespace errors | `git diff --check HEAD` | Passed |
| API startup without encryption key | Invoke startup with key absent in isolated environment | Correctly rejected |
| Dashboard/API startup with test key | Streamlit AppTest and temporary API `/health` request | Passed; HTTP 200, temporary server/data cleaned up |

Commands use executables from `.venv/Scripts` on Windows. Tests receive isolated
registries and ephemeral encryption keys; they do not configure a persistent
deployment key or apply migration to existing user uploads. These are the local
results, not a claim that a remote CI run or every supported platform passed.
The selected lint, type-check and high-severity security profiles are the existing
CI gates, not a security certification or exhaustive static analysis.

The five skips are environmental: two Windows symlink-creation privilege checks
(`test_artifact_integrity.py` and `test_dataset_references.py`) and three optional
development-only PyTorch tests (`test_trained_sequence_fixture.py`). Other
canonical-target, encrypted-loading and provided sequence-fixture regressions
passed; skipped cases are not counted as passes.

The run emitted nonblocking FastAPI lifecycle deprecations, SHAP/Matplotlib color
API deprecations and SQLite connection `ResourceWarning` messages in existing
scan paths. They remain recorded warnings; Phase 4 does not claim to fix them
or to make the project warning-free.

## Six Historical Regressions

`tests/test_phase4_ui_regressions.py` adds 11 focused cases using Streamlit
AppTest, parsed rendered HTML and a source-level CSS guard:

| Earlier issue | Verified behavior |
|---|---|
| Threat posture stuck at HIGH RISK | TM-014 remains visibly not assessed and cannot floor the assessed headline; clean assessed evidence gives LOW RISK and no evidence gives NOT ASSESSED. |
| Duplicate inline green theme | `dashboard/app.py` has no inline style block and calls the shared `dashboard.theme` injector. |
| Assurance legend always highlights A | Only the actual A/B/C/D tier is active; unavailable scores activate none. |
| Dangling login divider and marketing claim | Neither authentication mode renders an orphan OR divider or enterprise-encryption claim. |
| Missing password confirmation | Mismatched confirmation blocks registration before `create_user`; matching values reach the registration path. |
| Exposed report filesystem path | The Generated Artifact label and download filename show only the filename, not the absolute server directory. |

No production UI changes were needed for these six checks. This is behavioral
regression coverage, not a fresh pixel-by-pixel review at every viewport size.

## Combined Diff Scope

The independent audit found no unexplained application-source changes. The
working tree was already dirty; existing changes and generated output were not
reverted. New files are included in this summary even though ordinary `git diff`
does not display untracked additions.

Snapshot after the Phase 4 documentation changes: 55 modified, 10 deleted and
22 untracked files (87 paths). The tracked-only diff reports 65 changed files,
1,648 insertions and 1,958 deletions; those line totals exclude all 22 untracked
additions, including this note and the new security modules/regression files.
These are working-tree changes against the base above, not a new commit.

| Group | Scope across the hardening phases |
|---|---|
| Retired files | Delete native importer/worker/CLI/tests, their two requirements files, native image definition, root image/compose definitions and container ignore file. No replacement native importer or container dependency is introduced. |
| Core | Add `artifact_integrity.py`, `report_evidence.py`, `model_storage.py` and `model_access.py`; integrate immutable baselines, report citations, authenticated memory reads, logical hashes/sizes, worker context and the new storage registry. |
| Assessment modules | Cite actual fields in every finding, expose observed early-error evidence, use logical model sizes, and guard report/export/runtime actions. Scoring weights, thresholds and deployment decisions are not redesigned. |
| API/dashboard | Encrypt model/package intake before disk publication; retain auth and owner scoping; preserve the requesting actor on reads; validate deferred report downloads; require the runtime encryption key; bound in-memory multipart intake. |
| Model/package safety | Reject nested ONNX external tensors before checker/runtime execution; validate package destinations before writes so aliases cannot overwrite encrypted models with plaintext. Existing isolation and GPU policy are retained. |
| Scripts | Integrate scan checks and access context; add explicit verified `encrypt_model_storage.py`; remove the retired development requirements reference. |
| Documentation/configuration | Document final ONNX/PCAP/GPU scope, bring-your-own export, required key and migration, honest protection limits, and empty secret placeholders in `.env.example`. |
| Requirements/CI | Require the tested Streamlit deferred-download API version; supply an ephemeral CI encryption key; remove the container-build step. |
| Tests | Cover integrity/tampering, real scan workflows, evidence citations, encrypted loaders/packages/uploads, audit/rate limits, migration/recovery, isolated state and the six historical fixes. Plaintext-storage assertions are updated to ciphertext plus original logical-byte checks. |
| Phase 4 close-out | Add the focused UI regression file, this verification report and the README security-control summary/clarifications. |

### Existing Changes Preserved

- `core/pcap_ingestion.py` differs from HEAD only by the previously approved
  common IPv4/IPv6 ESP rejection. It was not modified by these verification steps.
  Its SHA-256 remains
  `8A17767DD3A1215F56C548D81D2A31BAAB245F148FFF936D7034F641387A3CAF`.
- `tests/test_pcap_ingestion_adversarial.py` retains that earlier approved coverage.
- `reports/trust_reports/traffic_rf_v1_phase3_trust_report.json` was already a
  dirty generated artifact. It is not a source deliverable or clean release
  snapshot and has not been reverted or treated as a verified historical report.
- Native-conversion defaults in dataset references are removed in favor of
  explicit `input_type`; owner-reference authorization guards remain in place.
- The earlier theme, authentication, tier, topbar and threat-model implementations
  are preserved. New dashboard changes concern secure intake/report actions and
  startup configuration, not a visual redesign.

The GPU provider file is not byte-identical to HEAD: Phase 3 replaces actual
file-backed runtime inputs with decrypted memory bytes, including CPU fallback.
Provider selection, fallback policy, profiling and execution-evidence logic are
unchanged. Phase 1's removal of native imports did not remove GPU execution.

## Limits and Deployment Actions

- Real CUDA hardware execution has not been verified locally. CPU inference and
  GPU policy/fallback behavior have regression coverage; neither implies every
  graph node runs on a GPU. `strict_gpu_guarantee` remains false.
- Optional dependencies and filesystem-privilege limitations account for the
  five skipped cases listed above, not failed security regressions.
- Finding citations establish structural traceability, not proof that a measured
  value is true or its written interpretation is valid.
- Stored uploaded/extracted models and uploaded packages are encrypted. Public
  fixtures intentionally remain plaintext; datasets, metadata and reports are
  not covered by model-at-rest encryption.
- Application-mediated model reads are audited. Direct filesystem access is not
  OS-audited by this application; compromise of the runtime key, registry or
  server is outside the protection claim.
- The unusual-access detector is a persistent configurable threshold on distinct
  owner/path identities, not a learned classifier. A source package and its
  extracted model count separately.
- Required deployment setup remains explicit: retain one persistent
  `CREDORA_MODEL_ENCRYPTION_KEY`, back up the registry/key securely, then inventory
  and deliberately migrate legacy uploads in a maintenance window. Unknown or
  changed files must not be assigned new baselines to make migration pass.
- No deployment key was generated or installed, no automatic user-data migration
  was performed, and no commit or push was made as part of final verification.

See [security setup and migration](../README.md#phase-3-security-setup-protected-model-storage)
for operator commands. A passing assessment score never overrides a failed
mandatory security or deployment gate.
