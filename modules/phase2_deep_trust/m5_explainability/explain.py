from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd

from core.report_schema import Finding, ModuleResult


def _extract_estimator(model):
    if hasattr(model, "named_steps"):
        for name in ["classifier", "model", "estimator", "rf"]:
            if name in model.named_steps:
                return model.named_steps[name]
        return list(model.named_steps.values())[-1]
    return model


def explain_model(model_path: str | Path, dataset_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    findings: list[Finding] = []
    try:
        model = joblib.load(model_path)
        data = pd.read_csv(dataset_path)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult("explainability", "fail", 0, "Explainability could not run.", [Finding("explainability", "Explainability failed", "high", str(exc), "Use a supported scikit-learn model with readable feature metadata.")])

    target_column = metadata.get("target_column", "label")
    feature_columns = metadata.get("expected_features") or [column for column in data.columns if column != target_column]
    feature_columns = [column for column in feature_columns if column in data.columns]
    estimator = _extract_estimator(model)

    importances = getattr(estimator, "feature_importances_", None)
    if importances is None:
        return ModuleResult(
            module="explainability",
            status="warning",
            score=60,
            summary="Model does not expose native feature importance.",
            findings=[Finding("explainability", "Limited explainability", "medium", "The uploaded model does not expose feature_importances_.", "Use Random Forest, XGBoost, or add SHAP/permutation explainability for this model type.")],
            details={"top_features": [], "method": "not_available"},
        )

    if len(importances) != len(feature_columns):
        transformed_count = len(importances)
        top_features = [{"feature": f"transformed_feature_{idx}", "importance": round(float(value), 5)} for idx, value in enumerate(importances[:20])]
        findings.append(Finding("explainability", "Feature names transformed by pipeline", "low", f"Model exposes {transformed_count} transformed feature importance value(s).", "For full feature names, store preprocessing output feature names in metadata."))
    else:
        ranked = sorted(zip(feature_columns, importances), key=lambda item: item[1], reverse=True)
        top_features = [{"feature": name, "importance": round(float(value), 5)} for name, value in ranked[:20]]

    top_importance = top_features[0]["importance"] if top_features else 0.0
    concentration = sum(item["importance"] for item in top_features[:3]) if top_features else 0.0
    score = 100.0
    if top_importance > 0.65:
        score -= 25
        findings.append(Finding("explainability", "Over-reliance on one feature", "medium", f"Top feature contributes {top_importance:.2f} importance.", "Check whether this feature is stable and not easy to manipulate."))
    if concentration > 0.85:
        score -= 15
        findings.append(Finding("explainability", "Feature importance is concentrated", "low", f"Top three features contribute {concentration:.2f} total importance.", "Validate the model on broader traffic patterns."))
    if not findings:
        findings.append(Finding("explainability", "Feature importance available", "info", "The model exposes usable feature-importance evidence."))

    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    return ModuleResult(
        module="explainability",
        status=status,
        score=round(score, 2),
        summary=f"Extracted top feature influences using native {estimator.__class__.__name__} importance.",
        findings=findings,
        details={"method": "feature_importances_", "top_features": top_features, "top_feature_importance": round(float(top_importance), 5), "top_3_importance": round(float(concentration), 5)},
    )
