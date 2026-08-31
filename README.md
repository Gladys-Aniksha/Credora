# TrustAI Sentinel

**A trust and security assessment framework for encrypted traffic classification models that verifies model integrity, evaluates classifier performance, scans security risks, tracks trust drift, and generates deployment-readiness reports.**

---

## 1. Vision

> TrustAI Sentinel helps users answer one core question: "Can I trust this encrypted traffic classification model enough to deploy it?"

Every module in this repository should trace back to this sentence. If a feature does not help evaluate the security, reliability, explainability, or deployment readiness of an encrypted traffic classification model, it does not belong in v1.

---

## 2. Why this project (honest framing)

Encrypted traffic classification is an **established cybersecurity and machine learning research area**. Many systems already classify encrypted network traffic using flow-level features such as packet size, packet timing, flow duration, byte counts, and TLS-related metadata.

Dependency scanners such as `pip-audit` also already exist, and model security scanners exist for checking unsafe ML model formats.

**We are not claiming to invent encrypted traffic classification or dependency vulnerability scanning.** Our contribution is the trust-evaluation layer built around the classifier:

- A **combined trust score** that considers model integrity, dependency risk, classifier performance, AI-specific vulnerabilities, toolchain risk, and version history.
- A **Trust Drift Timeline** that compares model versions and detects suspicious changes such as F1 score drops, hash changes, removed signatures, or newly introduced vulnerable dependencies.
- A **deployment-readiness dashboard and report** that explains whether the encrypted traffic classifier is secure, reliable, and ready to use.

Keep this distinction explicit in any pitch, paper, or demo. The project is strongest when presented as a practical trust and security evaluation system for encrypted traffic classification models.

---

## 3. System Architecture

```text
                    +-----------------------------+
                    |            User             |
                    | uploads model + dataset     |
                    | requirements + metadata     |
                    +--------------+--------------+
                                   |
                                   v
                    +-----------------------------+
                    |         Dashboard UI         |
                    | Streamlit / web interface   |
                    +--------------+--------------+
                                   |
                                   v
                    +-----------------------------+
                    |        FastAPI Backend       |
                    | scan orchestration + APIs   |
                    +--------------+--------------+
                                   |
        +--------------------------+--------------------------+
        |                          |                          |
        v                          v                          v
+------------------+      +------------------+      +----------------------+
| Model            |      | Dependency       |      | Encrypted Traffic    |
| Verification     |      | Scanner          |      | Classifier Eval      |
| hash/signature   |      | CVE/OSV checks   |      | metrics + matrix     |
+---------+--------+      +---------+--------+      +----------+-----------+
          |                         |                          |
          +-------------------------+--------------------------+
                                    |
                                    v
                    +-----------------------------+
                    |  AI Security + Toolchain    |
                    |  risk rules + permissions   |
                    +--------------+--------------+
                                   |
                                   v
                    +-----------------------------+
                    |     Trust Score Engine      |
                    | weighted deployment score   |
                    +--------------+--------------+
                                   |
                     +-------------+-------------+
                     |                           |
                     v                           v
          +----------------------+     +----------------------+
          | Trust Drift Timeline |     | Report Generator     |
          | version comparison   |     | model card + signed  |
          +----------+-----------+     | trust report         |
                     |                 +----------+-----------+
                     +-----------+----------------+
                                 |
                                 v
                    +-----------------------------+
                    | SQLite / PostgreSQL DB      |
                    | models, scans, scores       |
                    +-----------------------------+
```

---

## 4. Full Repository Structure

```text
trustai-sentinel/
|
|-- README.md
|-- LICENSE
|-- .gitignore
|-- requirements.txt
|-- docker-compose.yml
|-- architecture.md
|-- roadmap.md
|
|-- docs/
|   |-- project_proposal.md
|   |-- architecture.md
|   |-- trust_score_methodology.md
|   |-- trust_drift_timeline.md
|   |-- scope.md
|   |-- api_documentation.md
|   |-- testing_plan.md
|   |-- diagrams/
|   |-- research_notes/
|   |-- model_cards/
|   `-- reports/
|
|-- core/
|   |-- __init__.py
|   |-- config.py
|   |-- db.py
|   |-- hashing.py
|   |-- report_schema.py
|   |-- logging_config.py
|   `-- model_card.py
|
|-- modules/
|   |
|   |-- phase1_foundation/
|   |   |
|   |   |-- m1_model_verification/
|   |   |   |-- verifier.py
|   |   |   |-- models.py
|   |   |   `-- report.py
|   |   |
|   |   |-- m2_dependency_scanner/
|   |   |   |-- scanner.py
|   |   |   |-- cve_client.py
|   |   |   `-- report.py
|   |   |
|   |   |-- m8_etc_classifier/
|   |   |   |-- features/
|   |   |   |   |-- flow_features.py
|   |   |   |   `-- tls_features.py
|   |   |   |-- datasets/
|   |   |   |   `-- loader.py
|   |   |   |-- train.py
|   |   |   |-- model.py
|   |   |   |-- predict.py
|   |   |   `-- evaluate.py
|   |   |
|   |   |-- m11_trust_score/
|   |   |   |-- aggregator.py
|   |   |   |-- weights.py
|   |   |   `-- report.py
|   |   |
|   |   `-- m12_trust_drift_timeline/
|   |       |-- tracker.py
|   |       |-- diff.py
|   |       |-- anomaly.py
|   |       `-- report.py
|   |
|   |-- phase2_intelligence/
|   |   |
|   |   |-- m3_ai_vuln_scanner/
|   |   |   |-- scanner.py
|   |   |   |-- rules.py
|   |   |   `-- report.py
|   |   |
|   |   |-- m4_adversarial_testing/
|   |   |   |-- perturbation.py
|   |   |   |-- extraction_probe.py
|   |   |   `-- report.py
|   |   |
|   |   |-- m9_explainability/
|   |   |   |-- explainer.py
|   |   |   `-- narrative.py
|   |   |
|   |   |-- m10_threat_intel/
|   |   |   |-- atlas_mapper.py
|   |   |   |-- ip_reputation.py
|   |   |   `-- report.py
|   |   |
|   |   `-- m13_ai_toolchain_risk/
|   |       |-- scanner.py
|   |       |-- manifest_parser.py
|   |       |-- permission_analyzer.py
|   |       |-- risk_rules.py
|   |       `-- report.py
|   |
|   `-- phase3_operations/
|       |-- m5_secure_deployment/
|       |   `-- gatekeeper.py
|       |
|       |-- m6_runtime_integrity/
|       |   `-- watcher.py
|       |
|       `-- m7_drift_detection/
|           `-- drift_monitor.py
|
|-- api/
|   |-- main.py
|   |-- dependencies.py
|   `-- routes/
|       |-- models.py
|       |-- scan.py
|       |-- trust_score.py
|       |-- timeline.py
|       |-- toolchain_risk.py
|       |-- reports.py
|       `-- alerts.py
|
|-- dashboard/
|   |-- app.py
|   |-- pages/
|   |   |-- 1_model_registry.py
|   |   |-- 2_trust_score.py
|   |   |-- 3_encrypted_traffic_classifier.py
|   |   |-- 4_alerts_drift.py
|   |   |-- 5_trust_drift_timeline.py
|   |   `-- 6_ai_toolchain_risk.py
|   `-- components/
|       |-- score_card.py
|       |-- finding_table.py
|       |-- metric_cards.py
|       `-- timeline_chart.py
|
|-- signing/
|   |-- sign_report.py
|   `-- verify_report.py
|
|-- data/
|   |-- raw/
|   |-- processed/
|   |-- sample_models/
|   |-- sample_requirements/
|   `-- tool_configs/
|
|-- reports/
|   |-- trust_reports/
|   |-- signed_reports/
|   `-- model_cards/
|
|-- scripts/
|   |-- train_classifier.py
|   |-- evaluate_classifier.py
|   |-- run_full_scan.py
|   |-- generate_report.py
|   `-- seed_demo_data.py
|
|-- tests/
|   |-- test_m1_model_verification.py
|   |-- test_m2_dependency_scanner.py
|   |-- test_m8_classifier.py
|   |-- test_m11_trust_score.py
|   |-- test_m12_trust_drift_timeline.py
|   |-- test_m13_ai_toolchain_risk.py
|   `-- fixtures/
|
`-- deployment/
    |-- docker/
    |-- nginx/
    `-- production/
```

### A note on data folders

Data lives in multiple places on purpose because they represent different stages:

| Folder | Contains |
|---|---|
| `data/raw/` | Original encrypted traffic datasets or uploaded test files |
| `data/processed/` | Cleaned flow-feature CSV files used for model training and evaluation |
| `data/sample_models/` | Demo classifier models such as `traffic_rf_v1.pkl` and `traffic_rf_v2.pkl` |
| `data/tool_configs/` | Sample MCP/tool/plugin configuration files for toolchain risk scanning |
| `reports/` | Generated model cards, trust reports, and signed reports |

### A note on Docker

- `docker-compose.yml` in the root is for local development orchestration: API, dashboard, and database.
- `deployment/docker/` is for later production-style container configuration.

---

## 5. Module Responsibility Table

| Module | Input | Output | v1 Priority |
|---|---|---|---|
| `model_verification` | Uploaded model file + metadata | Hash/signature/type status + risk findings | High |
| `dependency_scanner` | `requirements.txt` or lock file | Vulnerability list + dependency risk level | High |
| `etc_classifier` | Encrypted traffic flow dataset | Predictions, metrics, confusion matrix | High |
| `trust_score` | Results from core modules | Weighted trust score + deployment status | High |
| `trust_drift_timeline` | Current and previous model scan records | Version diff + trust drift alerts | High |
| `explainability` | Trained classifier + feature vectors | Top decision features + explanation text | Medium |
| `ai_vuln_scanner` | Model/project files/configs | AI-specific vulnerability findings | Medium |
| `ai_toolchain_risk` | MCP/tool/plugin config files | Permission risk findings + recommendations | Medium |
| `report_generator` | Final scan results | Model card, trust report, signed report | Medium |

---

## 6. MVP Inputs

| Input | Example | Purpose |
|---|---|---|
| Trained model | `traffic_rf_v3.pkl` | Model artifact to verify and evaluate |
| Test dataset | `encrypted_traffic_test.csv` | Flow-feature data for classifier evaluation |
| Dependencies | `requirements.txt` | Package vulnerability scanning |
| Metadata | `model_metadata.json` | Model name, version, dataset, algorithm, owner |
| Tool config | `mcp.json` or `tool_config.json` | Optional AI toolchain risk scanning |

The encrypted traffic classifier should use metadata only. The system does **not** decrypt packet contents.

---

## 7. Solo Build Roadmap

| Phase | Scope | Success Criterion |
|---|---|---|
| **0** | Project setup, shared schemas, database, sample data | Demo files load and scan records can be stored |
| **1** | Model verification, dependency scanner, encrypted traffic classifier evaluation, trust score | A full scan produces model status, dependency findings, classifier metrics, and a trust score |
| **2** | Trust Drift Timeline and dashboard views | Two model versions can be compared and the result is visible in the dashboard |
| **3** | Explainability, AI vulnerability scanner, AI toolchain risk scanner, report generation | The dashboard explains risks and generates a model card/trust report |
| **4** | Signed reports and optional deployment checks | Reports can be signed and verified; lightweight deployment-readiness checks are available |

This is a solo project, so the build order matters. The first complete version should focus on the foundation: model verification, dependency scanning, encrypted traffic classifier evaluation, trust score, and trust drift timeline. Later features should be added only after the core workflow is working end to end.

---

## 8. Tech Stack

| Layer | Stack |
|---|---|
| Dashboard | Streamlit |
| Backend | FastAPI, Pydantic, Uvicorn |
| Database | SQLite for MVP, PostgreSQL later, SQLAlchemy |
| ML / ETC classifier | pandas, numpy, scikit-learn, joblib, XGBoost optional |
| Explainability | scikit-learn feature importance, SHAP optional |
| Dependency scanning | `pip-audit`, OSV API, packaging |
| Security utilities | hashlib, cryptography, filetype/python-magic |
| Toolchain scanning | JSON/YAML parsers, custom permission rules |
| Visualization | Plotly, Matplotlib, Seaborn |
| Reports | Jinja2, JSON export, ReportLab or WeasyPrint |
| Deployment | Docker, Docker Compose |

---

## 9. Development Notes

This is an individual academic/portfolio project. The repository is organized to keep the implementation realistic for a solo developer:

- Build one working core pipeline before filling every optional module.
- Keep later-phase folders as planned modules if they are not implemented yet.
- Clearly document which features are fully implemented, partially implemented, or planned.
- Prioritize real classifier metrics and honest trust-score methodology over broad but shallow features.

Suggested local run flow once implemented:

```text
1. Train or load a sample encrypted traffic classifier.
2. Start the FastAPI backend.
3. Start the Streamlit dashboard.
4. Upload the model, test dataset, requirements file, and metadata.
5. Run Full Scan.
6. Review classifier metrics, security findings, trust score, timeline, and report.
```

---

## 10. Independent Model Verification

Before comparing TrustAI Sentinel results, verify the encrypted traffic classifier outside the dashboard:

```powershell
cd "C:\Users\glady\Mini project"
& ".venv\Scripts\python.exe" scripts\verify_model_independent.py
```

This independent script loads the model and test dataset directly, runs predictions, and writes a baseline report to:

```text
reports/model_cards/independent_verification_report.json
```

Baseline result for the current sample classifier:

| Metric | Value |
|---|---:|
| Rows evaluated | 225 |
| Feature count | 8 |
| Accuracy | 1.0 |
| Weighted F1 | 1.0 |
| Macro F1 | 1.0 |

Files used:

| Purpose | File |
|---|---|
| Model | `data/sample_models/traffic_rf_v1.joblib` |
| Test dataset | `data/processed/encrypted_traffic_test.csv` |
| Metadata | `data/metadata/traffic_rf_v1_metadata.json` |

Use this result as the ground truth. When the same model and dataset are scanned in TrustAI Sentinel, the classifier metrics should match this independent report.

---

## 11. Current Working Prototype Commands

Use these commands from the real project folder:

```powershell
cd "C:\Users\glady\Mini project"
```

### Start the dashboard

```powershell
& ".venv\Scripts\python.exe" -m streamlit run dashboard\app.py --server.port 8501
```

Open:

```text
http://localhost:8501
```

In the sidebar, open **Upload & Analyze Model**, choose **Demo model**, then click **Analyze model now**.

### Run the full TrustAI scan from terminal

```powershell
& ".venv\Scripts\python.exe" scripts\run_phase1_scan.py
```

This runs the complete Phase 1-3 assessment: model verification, dependency scanning, classifier evaluation, robustness, data drift, explainability, behavior analysis, model risk, adversarial validation, runtime integrity, the production deployment gate, trust drift, scoring, and report generation.

### Run Phase 3 automated tests

```powershell
& ".venv\Scripts\python.exe" -m pytest tests -q
```

The 13-test suite verifies adversarial scenarios, a deliberately evasive traffic holdout, production gate decisions, signed package trust, Zeek/CICFlowMeter conversion, rolling drift persistence, runtime history, and tamper alerts.

### Run the Phase 3 release gate

```powershell
& ".venv\Scripts\python.exe" scripts\phase3_release_gate.py --minimum-score 85
```

The command exits with code `0` only when the trust threshold and deployment decision pass. Add `--require-approved` when conditional releases must also fail CI.

### Monitor runtime model integrity

```powershell
& ".venv\Scripts\python.exe" scripts\runtime_integrity_monitor.py --interval 60
```

Every check is stored in SQLite. Hash or signature failures create deduplicated production alerts. Use `--checks 1` for a one-shot verification.

### Ingest Zeek or CICFlowMeter captures

```powershell
& ".venv\Scripts\python.exe" scripts\ingest_network_flows.py `
  --source C:\captures\conn.log `
  --format zeek `
  --output data\production_flows\latest.csv
```

For CICFlowMeter, use `--format cicflowmeter`. The converter writes the eight metadata-only classifier features without decrypting payloads.

### Analyze rolling production drift

```powershell
& ".venv\Scripts\python.exe" scripts\monitor_production_drift.py `
  --captured-csv data\production_flows\latest.csv `
  --window-size 250
```

Each window and any resulting alert are persisted in `data/registry/trustai_registry.sqlite3` and shown in **Trust Drift** and **Alerts**.

### Create a signed model package

```powershell
& ".venv\Scripts\python.exe" scripts\package_model.py keygen `
  --private-key data\signing_keys\release-private.pem `
  --public-key data\signing_keys\release-public.pem

& ".venv\Scripts\python.exe" scripts\package_model.py create `
  --model data\sample_models\traffic_rf_v1.joblib `
  --metadata data\metadata\traffic_rf_v1_metadata.json `
  --requirements data\sample_requirements\requirements_demo.txt `
  --private-key data\signing_keys\release-private.pem `
  --output data\packages\traffic_rf_v1.trustai

& ".venv\Scripts\python.exe" scripts\package_model.py verify `
  --package data\packages\traffic_rf_v1.trustai `
  --public-key data\signing_keys\release-public.pem
```

Keep private keys outside source control. Verification requires an external trusted public key, validates the Ed25519 signature, rejects unsafe archive paths, and checks every artifact hash before extraction.

### Run with containers

```powershell
docker compose up --build
```

The API runs at `http://localhost:8000` and the dashboard at `http://localhost:8501`. The GitHub Actions workflow runs all tests, executes the real release gate, and builds the same container image.

### Create and scan the Phase 3 evasive validation pack

```powershell
& ".venv\Scripts\python.exe" scripts\create_phase3_validation_pack.py
```

This keeps the legitimate trained model but shifts security-sensitive flow features toward benign patterns while preserving their true labels. Scan it with:

```powershell
& ".venv\Scripts\python.exe" scripts\run_phase1_scan.py `
  --model data\sample_models\traffic_rf_v1.joblib `
  --dataset data\phase3_validation\traffic_rf_v1_evasion_probe\evasive_traffic_test.csv `
  --requirements data\phase3_validation\traffic_rf_v1_evasion_probe\requirements.txt `
  --metadata data\phase3_validation\traffic_rf_v1_evasion_probe\metadata.json
```

### Test the classifier independently

```powershell
& ".venv\Scripts\python.exe" scripts\verify_model_independent.py
```

This checks the classifier without using TrustAI Sentinel. Use this output as the baseline for comparison with the dashboard.

### Test the classifier in a real-time simulation

```powershell
& ".venv\Scripts\python.exe" scripts\realtime_classifier_probe.py
```

This sends one encrypted-flow metadata record at a time into the trained classifier and prints live predictions.

Optional shorter run:

```powershell
& ".venv\Scripts\python.exe" scripts\realtime_classifier_probe.py --events 10 --delay 0.2
```

### Regenerate demo data and model

```powershell
& ".venv\Scripts\python.exe" scripts\seed_demo_data.py
```

This recreates the demo Random Forest classifier and sample encrypted-flow datasets.

---

## 12. Current Working Files

| Purpose | File |
|---|---|
| Streamlit dashboard | `dashboard/app.py` |
| Full scan runner | `scripts/run_phase1_scan.py` |
| Demo data/model generator | `scripts/seed_demo_data.py` |
| Independent classifier verifier | `scripts/verify_model_independent.py` |
| Real-time simulation probe | `scripts/realtime_classifier_probe.py` |
| Deep behavior analyzer | `modules/phase2_deep_trust/m8_behavior_analysis/behavior.py` |
| Phase 3 adversarial validator | `modules/phase3_operations/m4_adversarial_validation/adversarial.py` |
| Phase 3 deployment gate | `modules/phase3_operations/m5_secure_deployment/gatekeeper.py` |
| Phase 3 runtime integrity | `modules/phase3_operations/m6_runtime_integrity/watcher.py` |
| Scheduled integrity monitor | `modules/phase3_operations/m6_runtime_integrity/scheduler.py` |
| Zeek/CICFlowMeter collector | `modules/phase3_operations/m7_flow_ingestion/collector.py` |
| Rolling production monitor | `modules/phase3_operations/m8_production_monitoring/monitor.py` |
| Signed model package | `core/model_package.py` |
| Phase 3 release gate | `scripts/phase3_release_gate.py` |
| Container deployment | `Dockerfile`, `docker-compose.yml` |
| CI release gate | `.github/workflows/phase3-release-gate.yml` |
| Evasive validation pack generator | `scripts/create_phase3_validation_pack.py` |
| Automated Phase 3 tests | `tests/test_phase3_*.py` |
| Sample classifier model | `data/sample_models/traffic_rf_v1.joblib` |
| Test dataset | `data/processed/encrypted_traffic_test.csv` |
| Metadata | `data/metadata/traffic_rf_v1_metadata.json` |
| Demo requirements | `data/sample_requirements/requirements_demo.txt` |
| Independent baseline report | `reports/model_cards/independent_verification_report.json` |
| Normal Phase 3 report | `reports/trust_reports/traffic_rf_v1_phase3_trust_report.json` |
| Evasive Phase 3 report | `reports/trust_reports/traffic_rf_v1_evasion_probe_phase3_trust_report.json` |

---

## 13. Deep Assessment Levels

When a model scan starts, TrustAI Sentinel now reports assessment progress by level:

| Level | Assessment | What it checks |
|---|---|---|
| Level 0 | Intake | Reads metadata and prepares scan inputs |
| Level 1 | Integrity | Checks model format, SHA-256 hash, signature metadata, and artifact size |
| Level 2 | Supply Chain | Reviews dependency/package risk |
| Level 3 | Classifier Performance | Runs predictions and calculates accuracy, precision, recall, F1, and confusion matrix |
| Level 4 | Robustness | Perturbs flow features and checks prediction stability |
| Level 5 | Data Drift | Compares current traffic features against baseline training data |
| Level 6 | Explainability | Finds which flow features drive decisions |
| Level 7 | Behavior Analysis | Checks confidence, weak classes, suspicious-class recall, class confusion, and feature reliance |
| Level 8 | Model Risk | Reviews unsafe serialization, metadata completeness, and deployment risk |
| Level 9 | Adversarial Validation | Runs timing jitter, sensitive-flow evasion, and sensor feature-dropout scenarios |
| Level 10 | Runtime Integrity | Verifies the deployed artifact hash and signature baseline |
| Level 11 | Trust Scoring | Combines validation evidence into a preliminary production score |
| Level 12 | Deployment Gate | Applies mandatory trust, classifier, adversarial, integrity, and sensitive-recall thresholds |
| Level 13 | Trust Drift | Compares trust score against previous scans |
| Level 14 | Final Report | Writes the deployment decision, tailored fixes, JSON report, and DOCX report |

Recommendations are generated from the actual findings. For example, if a model has weak `Suspicious` recall, the report recommends adding more labeled suspicious flows and setting a deployment recall gate. If prediction confidence is low, it recommends an abstain/manual-review threshold. If one feature dominates behavior, it recommends validating that feature and adding alternate traffic features.

---

## 14. Phase 3 Production Validation

Phase 3 is complete for the project scope. The scanner now covers pre-deployment assessment and post-deployment operational monitoring.

The latest local release gate for the normal classifier scores `97.0/100`. Every mandatory score and integrity check passes, but a raw `.joblib` artifact remains **conditional** because pickle-family files must never be loaded from an untrusted source. The signed `.trustai` packaging workflow supplies the hardened, externally trusted path for release automation.

The real-model evasive validation profile scores `61.70/100` and is **blocked**. It produces `0.0` recall for `Suspicious`, confuses all 75 suspicious flows as `VPN`, detects high drift across all eight model features, and fails five production gate checks. This proves the scanner produces materially different evidence and fixes when model behavior becomes unsafe.

Completed Phase 3 operational milestones:

- continuous scheduled runtime hash monitoring with persisted evidence;
- captured-network flow ingestion from Zeek and CICFlowMeter;
- rolling production drift windows with deduplicated, acknowledgeable alerts;
- Ed25519-signed, hash-verified model packages using an external trust key;
- API endpoints and dashboard views for operational evidence;
- containerized API/dashboard deployment;
- CI execution of all tests, the real model release gate, and the container build.

Phase 4 remains responsible for signing and independently verifying final trust reports and for stronger deployment identity/key-management policy.

---

## 15. Real-Time Environment Note

The included real-time probe is a live simulation using encrypted-flow metadata. For captured traffic, use the Phase 3 Zeek/CICFlowMeter ingestion workflow; TrustAI Sentinel consumes collector output and does not sniff or decrypt packets itself.

For a real network environment, capture encrypted traffic with a flow generator such as Zeek, CICFlowMeter, or another packet-to-flow tool, then convert each flow into these model features:

```text
flow_duration
packet_count
avg_packet_size
bytes_sent
bytes_received
iat_mean
iat_std
flow_bytes_per_second
```

Those feature rows can then be passed into the trained classifier for live predictions.
