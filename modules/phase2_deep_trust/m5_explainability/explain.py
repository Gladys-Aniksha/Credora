from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from core.model_backend import ModelBackend, load_model_backend
from core.report_schema import Finding, ModuleResult
from core.sequence_data import load_sequence_dataset


def _shap_importance(model: ModelBackend, x_sample: pd.DataFrame) -> tuple[list[dict], str]:
    import shap

    background = x_sample.head(min(len(x_sample), 50))
    explained = x_sample.head(min(len(x_sample), 100))

    def prediction_fn(values) -> np.ndarray:
        frame = values if isinstance(values, pd.DataFrame) else pd.DataFrame(values, columns=x_sample.columns)
        probabilities = model.predict_proba(frame)
        return probabilities if probabilities is not None else model.predict(frame)

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
    if metadata.get("input_type", "tabular") == "sequence":
        try:
            model = load_model_backend(model_path, metadata)
            dataset = load_sequence_dataset(dataset_path, metadata)
            samples = dataset.features[: min(len(dataset.features), 20)]
            window = max(1, samples.shape[1] // 16)
            saliency: list[dict] = []
            for start in range(0, samples.shape[1], window):
                occluded = samples.copy()
                occluded[:, start : start + window] = metadata.get("pad_id", 0)
                original = model.predict_proba(samples)
                changed = model.predict_proba(occluded)
                if original is None or changed is None:
                    raise ValueError("Sequence model did not expose probability outputs for occlusion.")
                predicted = np.argmax(original, axis=1)
                drops = original[np.arange(len(original)), predicted] - changed[np.arange(len(changed)), predicted]
                saliency.append({"position_start": start, "position_end": min(start + window, samples.shape[1]), "saliency": round(float(np.mean(drops)), 6)})
            top = sorted(saliency, key=lambda item: item["saliency"], reverse=True)[:10]
            if top and top[0]["position_start"] < window * 2:
                findings.append(Finding("explainability", "Sequence saliency is concentrated near the beginning", "medium", "The first sequence positions have unusually high occlusion impact and may represent shortcut or header learning.", "Validate saliency on sequences from different capture sources and inspect whether early bytes are stable features."))
            else:
                findings.append(Finding("explainability", "Sequence occlusion saliency available", "info", "Credora measured how much each sequence window changes the original prediction probability."))
            return ModuleResult("explainability", "warning" if any(item.severity == "medium" for item in findings) else "pass", 75.0 if len(findings) > 1 else 100.0, "Measured sequence explanation using bounded sliding-window occlusion.", findings, {"input_type": "sequence", "method": "occlusion", "saliency": saliency, "top_saliency": top, "shap_attempted": False})
        except Exception as exc:  # noqa: BLE001
            return ModuleResult("explainability", "warning", 60, "Sequence occlusion explanation could not run.", [Finding("explainability", "Sequence explanation unavailable", "medium", str(exc), "Use an ONNX sequence model with probability outputs and a compatible NPZ dataset.")], {"input_type": "sequence", "method": "not_available", "saliency": []})
    try:
        model = load_model_backend(model_path, metadata)
        data = pd.read_csv(dataset_path)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult("explainability", "fail", 0, "Explainability could not run.", [Finding("explainability", "Explainability failed", "high", str(exc), "Use a supported scikit-learn model with readable feature metadata.")])

    target_column = metadata.get("target_column", "label")
    feature_columns = metadata.get("expected_features") or [column for column in data.columns if column != target_column]
    feature_columns = [column for column in feature_columns if column in data.columns]
    if not feature_columns:
        return ModuleResult("explainability", "fail", 0, "No feature columns were available for explanation.", [Finding("explainability", "Missing feature columns", "critical", "The uploaded dataset does not contain the expected feature columns.", "Upload a compatible dataset or fix expected_features metadata.")])

    top_features = model.feature_importance(feature_columns) or []
    top_features = [
        {"feature": str(item["feature"]), "importance": round(float(item["importance"]), 5)}
        for item in top_features[:20]
    ]
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
    method_label = "model-agnostic SHAP" if method == "shap" else "native model"
    return ModuleResult(
        module="explainability",
        status=status,
        score=round(score, 2),
        summary=f"Extracted top feature influences using {method_label} evidence.",
        findings=findings,
        details={"method": method, "top_features": top_features, "top_feature_importance": round(float(top_importance), 5), "top_3_importance": round(float(concentration), 5), "shap_attempted": method == "shap"},
    )
