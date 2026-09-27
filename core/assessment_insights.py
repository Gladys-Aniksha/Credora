from __future__ import annotations

from typing import Any

from core.report_schema import ModuleResult


MODULE_METHODS = {
    "model_verification": "Calculated the artifact SHA-256, checked its format and size, and compared it with supplied identity metadata.",
    "dependency_scanner": "Parsed the supplied dependency manifest and ran pip-audit to look for published package vulnerabilities.",
    "classifier_evaluation": "Ran the uploaded model against every labeled flow and calculated overall and per-class prediction metrics.",
    "robustness_testing": "Perturbed numeric traffic features and compared the changed predictions with the clean baseline.",
    "data_drift_detection": "Compared numeric feature distributions with the training baseline using Population Stability Index (PSI).",
    "explainability": "Inspected native estimator feature importance or SHAP fallback evidence to identify the traffic signals driving predictions.",
    "dataset_leakage": "Compared the uploaded holdout with the training baseline for exact overlap and train/test performance gaps.",
    "privacy_risk": "Compared prediction confidence on training-like and holdout rows to estimate memorization and membership-inference risk.",
    "behavior_analysis": "Examined class recall, confusion, probability confidence, and concentration of feature reliance.",
    "model_risk_analyzer": "Reviewed artifact serialization, size, metadata completeness, expected features, and signing evidence.",
    "adversarial_validation": "Re-ran inference under timing jitter, security-sensitive evasion, and sensor feature-dropout scenarios.",
    "runtime_integrity": "Recalculated the model hash and compared it with the approved runtime identity baseline.",
    "deployment_gate": "Applied mandatory trust, classifier, adversarial, integrity, and security-sensitive recall thresholds.",
    "trust_drift_timeline": "Compared the current trust result with earlier assessments for the same model identity.",
    "trust_score": "Combined module scores using the published Credora weighting policy.",
}


def _result_map(results: list[ModuleResult]) -> dict[str, ModuleResult]:
    return {result.module: result for result in results}


def _number(value: Any, digits: int = 3) -> str:
    try:
        return str(round(float(value), digits))
    except (TypeError, ValueError):
        return "not available"


def _names(items: list[dict], key: str, limit: int = 5) -> str:
    values = [str(item.get(key)) for item in items if item.get(key) not in (None, "")]
    return ", ".join(values[:limit]) or "none"


def _module_evidence(result: ModuleResult) -> str:
    details = result.details or {}
    module = result.module
    if module == "model_verification":
        return f"File {details.get('file_name', 'unknown')}, format {details.get('extension', 'unknown')}, size {_number(details.get('size_mb'))} MB, SHA-256 {details.get('sha256', 'not available')}."
    if module == "dependency_scanner":
        vulnerabilities = details.get("vulnerabilities", [])
        affected = sorted({str(item.get("package")) for item in vulnerabilities if item.get("package")})
        return f"Parsed {details.get('package_count', 0)} package(s); found {len(vulnerabilities)} vulnerability record(s){': ' + ', '.join(affected) if affected else ''}."
    if module == "classifier_evaluation":
        weak = details.get("weak_classes", [])
        confusions = details.get("confusion_pairs", [])
        evidence = f"Accuracy {_number(details.get('accuracy'))}, weighted F1 {_number(details.get('f1_score'))}, recall {_number(details.get('recall'))}."
        if weak:
            item = min(weak, key=lambda row: float(row.get("f1", 0)))
            evidence += f" Weakest class: {item.get('class')} (F1 {_number(item.get('f1'))}, recall {_number(item.get('recall'))})."
        if confusions:
            pair = confusions[0]
            evidence += f" Largest confusion: {pair.get('actual')} -> {pair.get('predicted')} ({pair.get('count')} flow(s))."
        return evidence
    if module == "robustness_testing":
        return f"Clean F1 {_number(details.get('baseline_f1'))}; perturbed F1 {_number(details.get('perturbed_f1'))}; F1 drop {_number(details.get('f1_drop'))}; prediction stability {_number(details.get('prediction_stability'))}."
    if module == "data_drift_detection":
        drifted = details.get("drifted_features", [])
        feature_rows = details.get("feature_drift", [])
        drifted_names = [
            str(item.get("feature")) if isinstance(item, dict) else str(item)
            for item in drifted
            if (item.get("feature") if isinstance(item, dict) else item)
        ]
        strongest = sorted(feature_rows, key=lambda row: float(row.get("psi", 0)), reverse=True)[:3]
        strongest_text = ", ".join(f"{row.get('feature')} (PSI {_number(row.get('psi'))})" for row in strongest)
        return f"Compared {details.get('common_feature_count', len(feature_rows))} feature(s); drifted features: {', '.join(drifted_names) or 'none'}{'; strongest shifts: ' + strongest_text if strongest_text else ''}."
    if module == "explainability":
        top = details.get("top_features", [])
        top_text = ", ".join(f"{row.get('feature')} ({_number(row.get('importance'))})" for row in top[:3])
        return f"Method: {details.get('method', 'not available')}; leading features: {top_text or 'not available'}."
    if module == "dataset_leakage":
        return f"Feature overlap {_number(details.get('feature_overlap_rate'))}; full-row overlap {_number(details.get('full_row_overlap_rate'))}; train F1 {_number(details.get('train_f1'))}; test F1 {_number(details.get('test_f1'))}; generalization gap {_number(details.get('generalization_gap'))}."
    if module == "privacy_risk":
        return f"Train mean confidence {_number(details.get('train_mean_confidence'))}; test mean confidence {_number(details.get('test_mean_confidence'))}; confidence gap {_number(details.get('confidence_gap'))}; high-confidence gap {_number(details.get('high_confidence_gap'))}."
    if module == "behavior_analysis":
        confidence = details.get("confidence", {})
        weak = details.get("weak_classes", [])
        confusion = details.get("confusion_pairs", [])
        evidence = f"Weak classes: {_names(weak, 'class')}; mean confidence {_number(confidence.get('mean_confidence'))}; low-confidence rate {_number(confidence.get('low_confidence_rate'))}."
        if confusion:
            pair = confusion[0]
            evidence += f" Main confusion: {pair.get('actual')} -> {pair.get('predicted')} ({pair.get('count')} flow(s))."
        return evidence
    if module == "model_risk_analyzer":
        return f"Artifact format {details.get('extension', 'unknown')}, size {_number(details.get('size_mb'))} MB, {details.get('expected_feature_count', 0)} declared feature(s), metadata fields: {', '.join(details.get('metadata_fields', [])) or 'none'}."
    if module == "adversarial_validation":
        return f"Worst scenario {details.get('worst_case_scenario', 'not available')}; worst F1 {_number(details.get('worst_case_f1'))}; maximum F1 drop {_number(details.get('max_f1_drop'))}; minimum stability {_number(details.get('minimum_prediction_stability'))}; security-sensitive recall {_number(details.get('worst_sensitive_recall'))}."
    if module == "runtime_integrity":
        return f"Integrity state {details.get('integrity_state', 'unknown')}; expected SHA-256 {details.get('expected_sha256', 'not available')}; observed SHA-256 {details.get('actual_sha256', 'not available')}."
    if module == "deployment_gate":
        failed = details.get("failed_checks", [])
        return f"Decision {details.get('decision', 'not run')}; failed mandatory checks: {', '.join(failed) or 'none'}; high-risk findings {details.get('high_risk_finding_count', 0)}; medium-risk findings {details.get('medium_risk_finding_count', 0)}."
    if module == "trust_drift_timeline":
        return f"Previous scans {details.get('previous_scan_count', 0)}; change from latest {_number(details.get('drop_from_latest'))}; distance from historical best {_number(details.get('drop_from_best'))}."
    if module == "trust_score":
        return f"Final weighted score {_number(result.score, 2)}/100; deployment decision {details.get('deployment_decision', 'not available')}."
    return result.summary


def build_analysis_trace(results: list[ModuleResult]) -> list[dict[str, Any]]:
    trace = []
    for index, result in enumerate(results, start=1):
        non_info = [finding for finding in result.findings if finding.severity != "info"]
        trace.append({
            "step": index,
            "module": result.module,
            "status": result.status,
            "score": round(float(result.score), 2),
            "method": MODULE_METHODS.get(result.module, "Evaluated the evidence produced by this assessment module."),
            "evidence": _module_evidence(result),
            "conclusion": result.summary,
            "issues_found": len(non_info),
            "issue_titles": [finding.title for finding in non_info],
        })
    return trace


def _plan_item(
    priority: str,
    module: str,
    title: str,
    evidence: str,
    diagnosis: str,
    fix: str,
    validation: str,
    finding_titles: list[str],
) -> dict[str, Any]:
    return {
        "priority": priority,
        "module": module,
        "title": title,
        "evidence": evidence,
        "diagnosis": diagnosis,
        "fix": fix,
        "validation": validation,
        "finding_titles": finding_titles,
    }


def build_remediation_plan(results: list[ModuleResult], model_name: str, metadata: dict | None = None) -> list[dict[str, Any]]:
    by_module = _result_map(results)
    metadata = metadata or {}
    plan: list[dict[str, Any]] = []

    classifier = by_module.get("classifier_evaluation")
    behavior = by_module.get("behavior_analysis")
    if classifier and classifier.status != "pass":
        details = classifier.details
        weak = details.get("weak_classes", [])
        confusions = details.get("confusion_pairs", [])
        weakest = min(weak, key=lambda row: float(row.get("f1", 0))) if weak else {}
        pair = confusions[0] if confusions else {}
        target = str(weakest.get("class", "the weakest class"))
        confused_with = str(pair.get("predicted", "a competing class"))
        count = int(pair.get("count", 0) or 0)
        related_behavior_titles = [
            finding.title
            for finding in (behavior.findings if behavior else [])
            if finding.severity != "info" and any(word in finding.title.lower() for word in ("class", "malicious", "suspicious", "confusion"))
        ]
        plan.append(_plan_item(
            "P0" if classifier.status == "fail" else "P1",
            "classifier_evaluation",
            f"Recover {target} detection",
            _module_evidence(classifier),
            f"{model_name} has not learned a reliable boundary for {target}; its largest observed confusion is with {confused_with} across {count} labeled flow(s).",
            f"Review the {target} -> {confused_with} rows, add correctly labeled examples near that boundary, rebalance or cost-weight {target}, retrain, and compare the new per-class confusion matrix with this report.",
            f"Do not release until {target} recall and F1 are both at least 0.90 and the {target} -> {confused_with} error count is materially reduced on an untouched holdout set.",
            [finding.title for finding in classifier.findings if finding.severity != "info"] + related_behavior_titles,
        ))

    drift = by_module.get("data_drift_detection")
    if drift and drift.status != "pass":
        feature_rows = sorted(drift.details.get("feature_drift", []), key=lambda row: float(row.get("psi", 0)), reverse=True)
        features = [str(row.get("feature")) for row in feature_rows[:4] if row.get("feature")]
        plan.append(_plan_item(
            "P0" if drift.status == "fail" else "P1",
            "data_drift_detection",
            "Rebuild the traffic baseline around observed shifts",
            _module_evidence(drift),
            f"The evaluation traffic no longer resembles the training distribution, led by {', '.join(features) or 'the reported numeric features'}.",
            f"Validate capture units and preprocessing for {', '.join(features) or 'the drifted features'}, label a representative recent traffic window, and retrain or recalibrate with that window instead of mixing unverified shifted data into training.",
            "Rerun PSI on a separate recent window; every release-critical feature should be below 0.25 and classifier performance must remain above its gate threshold.",
            [finding.title for finding in drift.findings if finding.severity != "info"],
        ))

    leakage = by_module.get("dataset_leakage")
    if leakage and leakage.status != "pass":
        details = leakage.details
        plan.append(_plan_item(
            "P0" if leakage.status == "fail" else "P1",
            "dataset_leakage",
            "Rebuild the holdout split before trusting accuracy",
            _module_evidence(leakage),
            "The uploaded evaluation data may not be independent enough to support the reported accuracy claim.",
            "Create a fresh holdout from raw traffic using time-aware or source-aware splitting, remove duplicate feature rows, lock the file, and rerun the scan without reusing training rows.",
            "Approve the accuracy claim only when exact overlap is 0%, the train/test F1 gap is below 0.05, and the same result holds on a recent untouched traffic window.",
            [finding.title for finding in leakage.findings if finding.severity != "info"],
        ))

    privacy = by_module.get("privacy_risk")
    if privacy and privacy.status != "pass":
        plan.append(_plan_item(
            "P1" if privacy.status == "warning" else "P0",
            "privacy_risk",
            "Reduce memorization and verify privacy risk",
            _module_evidence(privacy),
            "The model shows a train-vs-holdout confidence pattern that can make membership inference easier or leaves privacy risk unmeasured.",
            "Calibrate probability outputs, reduce overfitting with stronger regularization or pruning, and rerun a privacy audit with training and holdout baselines before deployment.",
            "The confidence gap should be below 0.04, high-confidence gap below 0.10, and privacy findings should be pass or explicitly accepted with evidence.",
            [finding.title for finding in privacy.findings if finding.severity != "info"],
        ))

    if behavior:
        confidence = behavior.details.get("confidence", {})
        low_rate = float(confidence.get("low_confidence_rate", 0) or 0)
        if low_rate > 0.20:
            plan.append(_plan_item(
                "P1",
                "behavior_analysis",
                "Add a measured low-confidence handling policy",
                _module_evidence(behavior),
                f"{low_rate:.1%} of evaluated flows fall below the current 0.65 confidence boundary, so automatic decisions are unreliable for that population.",
                "Calibrate probabilities on a validation set, choose an operating threshold from the precision-recall trade-off, and route predictions below that threshold to review or a safer fallback classifier.",
                "On a held-out calibration set, report coverage, error rate above the threshold, and review volume below it; approve only a threshold that meets the operational error budget.",
                [finding.title for finding in behavior.findings if "confidence" in finding.title.lower()],
            ))
        top = behavior.details.get("top_features", [])
        if top and float(top[0].get("importance", 0)) > 0.45:
            feature = str(top[0].get("feature"))
            importance = float(top[0].get("importance", 0))
            plan.append(_plan_item(
                "P1",
                "behavior_analysis",
                f"Reduce dependence on {feature}",
                f"{feature} contributes {importance:.3f} of total model importance.",
                f"The model can change behavior sharply if {feature} is spoofed, missing, or captured differently.",
                f"Run an ablation test without {feature}, add independent timing and byte-ratio signals, and retrain only if the alternate evidence preserves class recall.",
                f"Require less than 0.45 importance for any single feature and less than a 0.05 F1 drop when {feature} is perturbed or unavailable.",
                [finding.title for finding in behavior.findings if "relies" in finding.title.lower()],
            ))

    adversarial = by_module.get("adversarial_validation")
    if adversarial and adversarial.status != "pass":
        details = adversarial.details
        scenario_name = str(details.get("worst_case_scenario", "the worst adversarial scenario"))
        scenarios = details.get("scenarios", [])
        scenario = next((row for row in scenarios if row.get("scenario") == scenario_name), {})
        changed = scenario.get("changed_features", [])
        sensitive = details.get("sensitive_labels", [])
        plan.append(_plan_item(
            "P0" if adversarial.status == "fail" else "P1",
            "adversarial_validation",
            f"Harden against {scenario_name}",
            _module_evidence(adversarial),
            f"The weakest attacked behavior occurs under {scenario_name}{' while changing ' + ', '.join(changed) if changed else ''}, affecting {', '.join(sensitive) or 'security-sensitive'} detection.",
            f"Add labeled training variants that reproduce {scenario_name}, preserve the original clean holdout, and tune the classifier against both clean and attacked samples rather than optimizing only aggregate accuracy.",
            "Require worst-case F1 and security-sensitive recall of at least 0.90 across every adversarial scenario before the release gate can pass.",
            [finding.title for finding in adversarial.findings if finding.severity != "info"],
        ))

    dependencies = by_module.get("dependency_scanner")
    if dependencies and any(finding.severity != "info" for finding in dependencies.findings):
        vulnerabilities = dependencies.details.get("vulnerabilities", [])
        packages = sorted({str(row.get("package")) for row in vulnerabilities if row.get("package")})
        fixes = sorted({str(version) for row in vulnerabilities for version in row.get("fix_versions", [])})
        fix = (
            f"Upgrade {', '.join(packages)} to audited fixed versions{': ' + ', '.join(fixes) if fixes else ''}, regenerate the lock file, and rerun pip-audit."
            if packages else
            "Install or repair pip-audit in the scanner environment, confirm vulnerability-database access, and rerun the dependency assessment so the release is based on a completed audit."
        )
        plan.append(_plan_item(
            "P0" if vulnerabilities else "P2",
            "dependency_scanner",
            "Complete dependency security evidence",
            _module_evidence(dependencies),
            "The software supply-chain result is incomplete or contains known vulnerable packages.",
            fix,
            "The next scan must complete without an audit error and return zero unresolved high or critical dependency vulnerabilities.",
            [finding.title for finding in dependencies.findings if finding.severity != "info"],
        ))

    verification = by_module.get("model_verification")
    model_risk = by_module.get("model_risk_analyzer")
    artifact_findings = [
        finding
        for result in [verification, model_risk]
        if result
        for finding in result.findings
        if finding.severity != "info"
    ]
    if artifact_findings:
        sha256 = verification.details.get("sha256") if verification else None
        extension = verification.details.get("extension") if verification else "unknown"
        plan.append(_plan_item(
            "P0" if any(finding.severity in {"critical", "high"} for finding in artifact_findings) else "P1",
            "model_verification",
            "Bind the model artifact to a trusted release identity",
            f"Artifact {model_name} uses {extension}; observed SHA-256 is {sha256 or 'not available'}.",
            "Pickle-family artifacts may execute code when loaded, and metadata-only signature claims do not establish an external chain of trust.",
            f"Create a signed .credora package for this exact SHA-256 using an offline Ed25519 private key, distribute only the public trust key to deployment, and reject raw {extension} uploads outside the trusted packaging pipeline.",
            "Verify the package with an independently supplied public key, then require the extracted model hash to equal the approved release hash before loading it.",
            [finding.title for finding in artifact_findings],
        ))

    runtime = by_module.get("runtime_integrity")
    if runtime and runtime.status != "pass":
        plan.append(_plan_item(
            "P0",
            "runtime_integrity",
            "Restore the approved runtime artifact",
            _module_evidence(runtime),
            "The model currently available to the serving process is missing, changed, or not tied to the approved identity.",
            "Stop model serving, restore the verified signed artifact from the release store, investigate the replacement event, and rotate deployment credentials if modification was unauthorized.",
            "Resume serving only after three consecutive integrity checks match the approved SHA-256 and no new tamper alert is created.",
            [finding.title for finding in runtime.findings if finding.severity != "info"],
        ))

    gate = by_module.get("deployment_gate")
    if gate and gate.details.get("decision") == "blocked":
        failed = gate.details.get("failed_checks", [])
        plan.append(_plan_item(
            "P0",
            "deployment_gate",
            "Keep deployment blocked until mandatory evidence passes",
            _module_evidence(gate),
            f"The release fails mandatory controls: {', '.join(failed) or 'see gate evidence'}.",
            "Resolve the P0 model and data items above, generate a new untouched evaluation report, and rerun the complete release gate; do not override the decision manually.",
            "Every mandatory check must report passed, with no high/critical finding and a final decision of approved or explicitly reviewed conditional according to policy.",
            [finding.title for finding in gate.findings if finding.severity != "info"],
        ))

    priority_order = {"P0": 0, "P1": 1, "P2": 2}
    plan.sort(key=lambda item: (priority_order.get(item["priority"], 9), item["module"], item["title"]))
    for index, item in enumerate(plan, start=1):
        item["id"] = f"FIX-{index:02d}"
    return plan

