from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from core.model_loading import load_checked_model
from core.report_schema import Finding, ModuleResult


def _extract_estimator(model):
    if hasattr(model, "named_steps"):
        for name in ["classifier", "model", "estimator", "rf"]:
            if name in model.named_steps:
                return model.named_steps[name]
        return list(model.named_steps.values())[-1]
    return model


def _native_importance(estimator, feature_columns: list[str]) -> tuple[list[dict], list[Finding]]:
    findings: list[Finding] = []
    importances = getattr(estimator, "feature_importances_", None)
    if importances is None:
        return [], findings
    if len(importances) != len(feature_columns):
        transformed_count = len(importances)
        top_features = [{"feature": f"transformed_feature_{idx}", "importance": round(float(value), 5)} for idx, value in enumerate(importances[:20])]
        findings.append(Finding("explainability", "Feature names transformed by pipeline", "low", f"Model exposes {transformed_count} transformed feature importance value(s).", "For full feature names, store preprocessing output feature names in metadata."))
        return top_features, findings
    ranked = sorted(zip(feature_columns, importances), key=lambda item: item[1], reverse=True)
    return [{"feature": name, "importance": round(float(value), 5)} for name, value in ranked[:20]], findings


def _shap_importance(model, x_sample: pd.DataFrame) -> tuple[list[dict], str]:
    import shap

    background = x_sample.head(min(len(x_sample), 50))
    explained = x_sample.head(min(len(x_sample), 100))
    prediction_fn = model.predict_proba if hasattr(model, "predict_proba") else model.predict
    explainer = shap.Explainer(prediction_fn, background)
    values = explainer(explained)
    raw_values = values.values
    if raw_values.ndim == 3:
        mean_abs = np.abs(raw_values).mean(axis=(0, 2))
    elif raw_values.ndim == 2:
        mean_abs = np.abs(raw_values).mean(axis=0)
    else:
        mean_abs = np.asarray([])
    total = float(mean_abs.sum()) or 1.0
    ranked = sorted(zip(explained.columns, mean_abs / total), key=lambda item: item[1], reverse=True)
    return [{"feature": name, "importance": round(float(value), 5)} for name, value in ranked[:20]], "shap"


def explain_model(model_path: str | Path, dataset_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    findings: list[Finding] = []
    try:
        model = load_checked_model(model_path)
        data = pd.read_csv(dataset_path)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult("explainability", "fail", 0, "Explainability could not run.", [Finding("explainability", "Explainability failed", "high", str(exc), "Use a supported scikit-learn model with readable feature metadata.")])

    target_column = metadata.get("target_column", "label")
    feature_columns = metadata.get("expected_features") or [column for column in data.columns if column != target_column]
    feature_columns = [column for column in feature_columns if column in data.columns]
    if not feature_columns:
        return ModuleResult("explainability", "fail", 0, "No feature columns were available for explanation.", [Finding("explainability", "Missing feature columns", "critical", "The uploaded dataset does not contain the expected feature columns.", "Upload a compatible dataset or fix expected_features metadata.")])

    estimator = _extract_estimator(model)
    top_features, native_findings = _native_importance(estimator, feature_columns)
    findings.extend(native_findings)
    method = "feature_importances_" if top_features else "not_available"

    if not top_features:
        try:
            top_features, method = _shap_importance(model, data[feature_columns])
            findings.append(Finding("explainability", "SHAP fallback explanation used", "info", "The model did not expose native feature importance, so Credora estimated model-agnostic SHAP influence on a bounded data sample."))
        except Exception as exc:  # noqa: BLE001
            return ModuleResult(
                module="explainability",
                status="warning",
                score=60,
                summary="Model does not expose usable native or SHAP feature importance.",
                findings=[Finding("explainability", "Limited explainability", "medium", f"Credora could not produce feature influence evidence: {exc}", "Use a model with feature_importances_, provide preprocessing feature names, or install a compatible SHAP explainer path for this model type.")],
                details={"top_features": [], "method": "not_available", "shap_attempted": True},
            )

    top_importance = top_features[0]["importance"] if top_features else 0.0
    concentration = sum(item["importance"] for item in top_features[:3]) if top_features else 0.0
    score = 100.0 if method != "not_available" else 60.0
    if top_importance > 0.65:
        score -= 25
        findings.append(Finding("explainability", "Over-reliance on one feature", "medium", f"Top feature contributes {top_importance:.2f} importance.", "Check whether this feature is stable and not easy to manipulate."))
    if concentration > 0.85:
        score -= 15
        findings.append(Finding("explainability", "Feature importance is concentrated", "low", f"Top three features contribute {concentration:.2f} total importance.", "Validate the model on broader traffic patterns."))
    if not findings:
        findings.append(Finding("explainability", "Feature importance available", "info", "The model exposes usable feature-importance evidence."))

    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    method_label = "model-agnostic SHAP" if method == "shap" else f"native {estimator.__class__.__name__}"
    return ModuleResult(
        module="explainability",
        status=status,
        score=round(score, 2),
        summary=f"Extracted top feature influences using {method_label} evidence.",
        findings=findings,
        details={"method": method, "top_features": top_features, "top_feature_importance": round(float(top_importance), 5), "top_3_importance": round(float(concentration), 5), "shap_attempted": method == "shap"},
    )
