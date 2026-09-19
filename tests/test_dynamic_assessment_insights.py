from core.assessment_insights import build_analysis_trace, build_remediation_plan
from core.report_schema import Finding, ModuleResult


def test_evasive_evidence_generates_specific_class_drift_and_attack_fixes() -> None:
    results = [
        ModuleResult(
            "classifier_evaluation",
            "fail",
            55.6,
            "Evaluated 225 encrypted traffic flows.",
            [Finding("classifier_evaluation", "Weak class-specific performance", "medium", "Suspicious recall is zero.")],
            {
                "accuracy": 0.667,
                "f1_score": 0.556,
                "recall": 0.667,
                "weak_classes": [{"class": "Suspicious", "f1": 0.0, "recall": 0.0}],
                "confusion_pairs": [{"actual": "Suspicious", "predicted": "VPN", "count": 75}],
            },
        ),
        ModuleResult(
            "data_drift_detection",
            "fail",
            20,
            "Detected strong drift.",
            [Finding("data_drift_detection", "High data drift detected", "high", "All features drifted.")],
            {
                "drifted_features": ["iat_mean", "flow_duration"],
                "feature_drift": [{"feature": "iat_mean", "psi": 1.8}, {"feature": "flow_duration", "psi": 0.9}],
            },
        ),
        ModuleResult(
            "adversarial_validation",
            "fail",
            30,
            "Sensitive-flow evasion failed.",
            [Finding("adversarial_validation", "Security-sensitive evasion weakness", "high", "Recall collapsed.")],
            {
                "worst_case_scenario": "sensitive_flow_evasion",
                "worst_case_f1": 0.55,
                "worst_sensitive_recall": 0.0,
                "max_f1_drop": 0.45,
                "minimum_prediction_stability": 0.66,
                "sensitive_labels": ["Suspicious"],
                "scenarios": [{"scenario": "sensitive_flow_evasion", "changed_features": ["iat_mean", "packet_count"]}],
            },
        ),
        ModuleResult(
            "deployment_gate",
            "fail",
            20,
            "Deployment blocked.",
            [Finding("deployment_gate", "Deployment blocked", "high", "Mandatory checks failed.")],
            {"decision": "blocked", "failed_checks": ["Classifier score", "Security-sensitive recall"]},
        ),
    ]

    plan = build_remediation_plan(results, "traffic_rf_v1_evasion_probe")
    combined = " ".join(f"{item['evidence']} {item['diagnosis']} {item['fix']} {item['validation']}" for item in plan)

    assert "Suspicious -> VPN" in combined
    assert "75 labeled flow" in combined
    assert "iat_mean" in combined
    assert "sensitive_flow_evasion" in combined
    assert "Security-sensitive recall" in combined
    assert any(item["priority"] == "P0" for item in plan)


def test_analysis_trace_records_method_evidence_and_conclusion() -> None:
    result = ModuleResult(
        "classifier_evaluation",
        "pass",
        97,
        "Classifier performance is strong.",
        [],
        {"accuracy": 0.98, "f1_score": 0.97, "recall": 0.96, "weak_classes": [], "confusion_pairs": []},
    )

    trace = build_analysis_trace([result])

    assert trace[0]["module"] == "classifier_evaluation"
    assert "every labeled flow" in trace[0]["method"]
    assert "weighted F1 0.97" in trace[0]["evidence"]
    assert trace[0]["conclusion"] == "Classifier performance is strong."


def test_phase2_leakage_and_privacy_generate_specific_remediation() -> None:
    results = [
        ModuleResult(
            "dataset_leakage",
            "warning",
            70,
            "Compared train and test rows.",
            [Finding("dataset_leakage", "Small train/test overlap detected", "medium", "Overlap found.")],
            {"feature_overlap_rate": 0.12, "full_row_overlap_rate": 0.08, "train_f1": 1.0, "test_f1": 0.82, "generalization_gap": 0.18},
        ),
        ModuleResult(
            "privacy_risk",
            "warning",
            74,
            "Compared confidence.",
            [Finding("privacy_risk", "Moderate memorization signal", "medium", "Confidence gap found.")],
            {"train_mean_confidence": 0.98, "test_mean_confidence": 0.90, "confidence_gap": 0.08, "high_confidence_gap": 0.14},
        ),
    ]

    trace = build_analysis_trace(results)
    plan = build_remediation_plan(results, "traffic_rf_v1")
    combined = " ".join(f"{item['title']} {item['fix']} {item['validation']}" for item in plan)

    assert any(step["module"] == "dataset_leakage" and "Feature overlap" in step["evidence"] for step in trace)
    assert any(step["module"] == "privacy_risk" and "confidence gap" in step["evidence"] for step in trace)
    assert "fresh holdout" in combined
    assert "Calibrate probability" in combined
