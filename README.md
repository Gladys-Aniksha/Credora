# Credora

**A trust and security assessment framework for encrypted traffic classification models that verifies model integrity, evaluates classifier performance, scans security risks, tracks trust drift, and generates deployment-readiness reports.**

## Current Implemented Workflow

Credora now runs a security-first model trust workflow:

- Phase 1 hardens uploads, API access, signed package trust, raw pickle/joblib handling, trusted hashes, and model loading preflight checks.
- Phase 2 adds deeper truthfulness checks: SHAP fallback explainability, train/test leakage detection, train/test F1 comparison, and privacy/memorization confidence-gap analysis.
- Phase 3 provides release workflow polish: signed `.credora` package release gates, CI validation, dashboard evidence, and one-command local verification.
- Phase 4 signs final JSON trust reports with Ed25519 and verifies them against an external trusted signer key.
- The model backend supports secured scikit-learn artifacts and structurally validated ONNX models through the same assessment pipeline.
- The dashboard provides username/password login, role-aware administration, owner-scoped data, production monitoring, reports, and the current Credora assurance-focused visual layout.

For the repeatable release and signing commands, see `docs/PHASE3_RUNBOOK.md` and `docs/PHASE4_RUNBOOK.md`.

## Multi-User Access and Data Isolation

Credora now supports username/password login for the dashboard and bearer-token authentication for the API. Each user owns their uploaded files, model registry entries, scan history, reports, drift windows, runtime integrity records, and alerts. Uploaders only see their own data; reviewers and admins can enable all-user visibility for review workflows.

`CREDORA_API_KEY` is required in every environment; Credora will refuse to start if it is missing. For local development, generate separate random values with `python -c "import secrets; print(secrets.token_urlsafe(48))"`, then place them in a gitignored `.env` file:

```dotenv
CREDORA_API_KEY=<generated service API key>
CREDORA_JWT_SECRET=<different generated JWT secret>
```

Never commit the `.env` file or reuse these values outside their intended deployment.

## Local Setup

For local development only, Credora creates a bootstrap administrator when the registry has no users. The default username is `admin` and the default password is `credora-admin`. Override these defaults before shared or deployed use by setting `CREDORA_BOOTSTRAP_ADMIN`, `CREDORA_BOOTSTRAP_EMAIL`, and `CREDORA_BOOTSTRAP_PASSWORD` in the same gitignored `.env` file or shell environment, then run:

```powershell
.\.venv\Scripts\python.exe scripts\migrate_add_users.py --show-users
```

The auth scheme assumes TLS when deployed beyond localhost. A JWT bearer token over plain HTTP should be treated as exposed.

## Supported Model Formats

Credora accepts flat, tabular classifiers in three formats:

- scikit-learn-compatible `.joblib` and `.pkl` artifacts, loaded only after pickle allow-list inspection and an isolated deserialization preflight;
- ONNX `.onnx` artifacts, structurally validated with `onnx.checker` and executed with ONNX Runtime's CPU provider;
- signed `.credora` packages for production-style integrity and provenance verification.

ONNX support uses the same evaluation, robustness, drift, explainability, privacy, behavior, adversarial, trust-scoring, and deployment-gate workflow as sklearn models. ONNX uploads are limited to 50 MB.

Both tabular CSV and sequence NPZ tracks are supported for compatible ONNX models. Offline classic-PCAP ingestion, optional CUDA provider selection and restricted weights-only PyTorch/Keras imports are also available; their exact formats, preprocessing contracts, isolation requirements and limitations are documented in [Extended assessment inputs](docs/EXTENDED_INPUTS.md). Unrestricted framework checkpoints and uploaded model code remain rejected.

To rebuild the sample ONNX model from the sample Random Forest:

```powershell
.\.venv\Scripts\python.exe scripts\build_test_onnx_model.py
```

---

## 1. Vision

> Credora helps users answer one core question: "Can I trust this encrypted traffic classification model enough to deploy it?"

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
credora/
|
|-- README.md, PHASE1_README.md, LICENSE
|-- requirements.txt, requirements-dev.txt
|-- Dockerfile, docker-compose.yml
|-- .github/workflows/phase3-release-gate.yml
|
|-- api/
|   |-- main.py
|   `-- routes/
|
|-- core/
|   |-- auth.py, config.py, db.py, storage.py
|   |-- hashing.py, security.py
|   |-- model_backend.py, model_loading.py, model_package.py
|   |-- report_schema.py, report_signing.py
|   `-- assessment_insights.py
|
|-- modules/
|   |-- phase1_foundation/
|   |   |-- m1_model_verification/
|   |   |-- m2_dependency_scanner/
|   |   |-- m8_etc_classifier/
|   |   `-- m11_trust_score/
|   |-- phase2_deep_trust/
|   |   |-- m3_robustness_testing/
|   |   |-- m4_data_drift/
|   |   |-- m5_explainability/
|   |   |-- m6_model_risk/
|   |   |-- m7_trust_drift/
|   |   |-- m8_behavior_analysis/
|   |   |-- m9_docx_report/
|   |   |-- m10_dataset_leakage/
|   |   `-- m11_privacy_risk/
|   `-- phase3_operations/
|       |-- m4_adversarial_validation/
|       |-- m5_secure_deployment/
|       |-- m6_runtime_integrity/
|       |-- m7_flow_ingestion/
|       `-- m8_production_monitoring/
|
|-- dashboard/
|   |-- app.py, theme.py
|   |-- components/ (overview, scan submission, top bar, shared controls)
|   `-- pages/ (authentication, administration, reports, production monitoring)
|
|-- data/
|   |-- processed/                 # encrypted-flow train/test CSV files
|   |-- sample_models/             # joblib and ONNX demo models
|   |-- sample_requirements/
|   |-- phase3_validation/
|   |-- production_flows/, production_windows/
|   |-- uploads/                   # user-scoped runtime artifacts
|   `-- registry/                  # SQLite runtime registry
|
|-- docs/PHASE3_RUNBOOK.md, docs/PHASE4_RUNBOOK.md
|-- reports/model_cards/, reports/trust_reports/
|-- scripts/                       # scan, signing, packaging, monitoring, verification
`-- tests/                         # unit, security, backend, dashboard, and phase tests
```

### A note on data folders

Data lives in multiple places on purpose because they represent different stages:

| Folder | Contains |
|---|---|
| `data/raw/` | Original encrypted traffic datasets or uploaded test files, when used |
| `data/processed/` | Cleaned flow-feature CSV files used for model training and evaluation |
| `data/sample_models/` | Demo classifier models such as `traffic_rf_v1.joblib` and `traffic_rf_v1.onnx` |
| `data/phase3_validation/` | Evasive validation packs for production-gate testing |
| `data/uploads/` | User-scoped uploaded models, datasets, requirements, metadata, and verified packages |
| `data/registry/` | SQLite users, models, scans, reports, drift windows, runtime checks, and alerts |
| `reports/` | Generated model cards, JSON/DOCX trust reports, and verification outputs |

### A note on Docker

- `docker-compose.yml` in the root is for local development orchestration: API, dashboard, and database.
- `Dockerfile` builds the API/dashboard image used by the local container workflow.

---

## 5. Module Responsibility Table

| Module | Input | Output | Status |
|---|---|---|---|
| `m1_model_verification` | Uploaded model + metadata | Hash, signature, format, and artifact-risk findings | Implemented |
| `m2_dependency_scanner` | Requirements file | Package vulnerability findings and dependency risk | Implemented |
| `m8_etc_classifier` | Encrypted flow metadata | Predictions, metrics, and confusion matrix | Implemented |
| `m11_trust_score` | Assessment results | Weighted trust score and deployment status | Implemented |
| `phase2_deep_trust` | Model, train/test data, and scan history | Robustness, drift, explainability, leakage, privacy, behavior, and report evidence | Implemented |
| `phase3_operations` | Release artifacts and captured flow data | Adversarial validation, deployment gate, runtime integrity, ingestion, and production drift | Implemented |
| `core.report_signing` | Final JSON report + trusted key | Ed25519 signature and independent verification result | Implemented |
| `core.auth` and `core.db` | Users, roles, uploads, and scan records | Owner-scoped multi-user registry and audit data | Implemented |
| `dashboard` and `api` | Authenticated scan inputs and registry data | Web dashboard, reports, admin controls, and API access | Implemented |
| `Phase 15 sequence track` | ONNX sequence safety, NPZ evaluation, input-aware scoring, sequence evidence, robustness, and adversarial validation | Implemented for bounded ONNX + NPZ inputs; raw PCAP intentionally excluded | Implemented |

---

## 6. MVP Inputs

| Input | Example | Purpose |
|---|---|---|
| Trained model | `traffic_rf_v1.joblib` or `traffic_rf_v1.onnx` | Model artifact to verify and evaluate |
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
| **4** | Signed final reports, trusted signer verification, multi-user access, ONNX support, and optional deployment checks | Reports can be signed and independently verified; authenticated users can run and review owner-scoped assessments |

This is a solo project, so the build order matters. The first complete version should focus on the foundation: model verification, dependency scanning, encrypted traffic classifier evaluation, trust score, and trust drift timeline. Later features should be added only after the core workflow is working end to end.

---

## 8. Tech Stack

| Layer | Stack |
|---|---|
| Dashboard | Streamlit |
| Backend | FastAPI, Pydantic, Uvicorn |
| Database | SQLite for MVP, PostgreSQL later, SQLAlchemy |
| ML / ETC classifier | pandas, numpy, scikit-learn, joblib, ONNX, ONNX Runtime, XGBoost optional |
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

Before comparing Credora results, verify the encrypted traffic classifier outside the dashboard:

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
| Observed evaluation accuracy | 0.94 |
| Weighted F1 | 1.0 |
| Macro F1 | 1.0 |

Files used:

| Purpose | File |
|---|---|
| Model | `data/sample_models/traffic_rf_v1.joblib` |
| Test dataset | `data/processed/encrypted_traffic_test.csv` |
| Metadata | `data/metadata/traffic_rf_v1_metadata.json` |

Use this result as the ground truth. When the same model and dataset are scanned in Credora, the classifier metrics should match this independent report.

---

## 11. Current Working Prototype Commands

Use these commands from the real project folder:

```powershell
cd "C:\Users\glady\Mini project"
```

### Run the full local verification suite

```powershell
& ".venv\Scripts\python.exe" scripts\verify_project.py
```

Add `--with-api --with-dashboard` to include local server smoke checks.

### Start the dashboard

```powershell
& ".venv\Scripts\python.exe" -m streamlit run dashboard\app.py --server.port 8501
```

Open:

```text
http://localhost:8501
```

In the sidebar, open **Upload & Analyze Model**, choose **Demo model**, then click **Analyze model now**.

### Run the full Credora scan from terminal

```powershell
& ".venv\Scripts\python.exe" scripts\run_phase1_scan.py
```

This runs the complete assessment: model verification, dependency scanning, classifier evaluation, robustness, data drift, explainability, leakage/holdout checks, privacy risk, behavior analysis, model risk, adversarial validation, runtime integrity, the production deployment gate, trust drift, scoring, and report generation.

### Run automated tests

```powershell
& ".venv\Scripts\python.exe" -m pytest tests -q
```

The test suite verifies Phase 1 security controls, Phase 2 truthfulness checks, adversarial scenarios, production gate decisions, signed package trust, flow conversion, rolling drift persistence, runtime history, and tamper alerts.

### Run the signed Phase 3 release gate

```powershell
& ".venv\Scripts\python.exe" scripts\package_model.py keygen `
  --private-key data\signing_keys\release-private.pem `
  --public-key data\signing_keys\release-public.pem

& ".venv\Scripts\python.exe" scripts\package_model.py create `
  --model data\sample_models\traffic_rf_v1.joblib `
  --metadata data\metadata\traffic_rf_v1_metadata.json `
  --requirements data\sample_requirements\requirements_demo.txt `
  --private-key data\signing_keys\release-private.pem `
  --output data\packages\traffic_rf_v1.credora

& ".venv\Scripts\python.exe" scripts\phase3_release_gate.py `
  --package data\packages\traffic_rf_v1.credora `
  --trust-key data\signing_keys\release-public.pem `
  --minimum-score 85
```

Raw `.joblib` release-gate runs are allowed for diagnostics but are capped at `70/100`; signed `.credora` packages are the release path. The command exits with code `0` only when the trust threshold and deployment decision pass. Add `--require-approved` when conditional releases must also fail CI.

### Sign and verify a final trust report (Phase 4)

Generate a report-signing key pair once, sign a completed JSON trust report, and verify it independently:

```powershell
& ".venv\Scripts\python.exe" scripts\generate_report_signing_keys.py `
  --private-key data\signing_keys\report-private.pem `
  --public-key data\signing_keys\report-public.pem

& ".venv\Scripts\python.exe" scripts\sign_trust_report.py `
  --report reports\trust_reports\traffic_rf_v1_phase3_trust_report.json `
  --private-key data\signing_keys\report-private.pem

& ".venv\Scripts\python.exe" scripts\verify_trust_report.py `
  --report reports\trust_reports\traffic_rf_v1_phase3_trust_report.json `
  --public-key data\signing_keys\report-public.pem
```

Keep report private keys outside source control. The verification command checks the report signature and the trusted signer identity; report signing is separate from signed model-package verification.

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

Each window and any resulting alert are persisted in `data/registry/credora_registry.sqlite3` and shown in **Trust Drift** and **Alerts**.

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
  --output data\packages\traffic_rf_v1.credora

& ".venv\Scripts\python.exe" scripts\package_model.py verify `
  --package data\packages\traffic_rf_v1.credora `
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

This checks the classifier without using Credora. Use this output as the baseline for comparison with the dashboard.

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
| Dashboard theme and overview | `dashboard/theme.py`, `dashboard/components/overview.py` |
| Dashboard authentication | `dashboard/pages/auth.py`, `core/auth.py` |
| Dashboard administration | `dashboard/pages/admin.py` |
| Reports and production monitoring pages | `dashboard/pages/reports.py`, `dashboard/pages/production_monitoring.py` |
| API and access control | `api/main.py`, `core/auth.py`, `core/db.py` |
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
| Model backend and ONNX support | `core/model_backend.py`, `scripts/build_test_onnx_model.py` |
| Phase 3 release gate | `scripts/phase3_release_gate.py` |
| Phase 4 report signing | `core/report_signing.py`, `scripts/sign_trust_report.py`, `scripts/verify_trust_report.py` |
| Container deployment | `Dockerfile`, `docker-compose.yml` |
| CI release gate | `.github/workflows/phase3-release-gate.yml` |
| Evasive validation pack generator | `scripts/create_phase3_validation_pack.py` |
| Automated Phase 3 tests | `tests/test_phase3_*.py` |
| Authentication, backend, ONNX, dashboard, and report-signing tests | `tests/test_auth.py`, `tests/test_model_backend.py`, `tests/test_onnx_backend.py`, `tests/test_dashboard_structure.py`, `tests/test_phase4_report_signing.py` |
| Sample classifier model | `data/sample_models/traffic_rf_v1.joblib` |
| Test dataset | `data/processed/encrypted_traffic_test.csv` |
| Metadata | `data/metadata/traffic_rf_v1_metadata.json` |
| Demo requirements | `data/sample_requirements/requirements_demo.txt` |
| Independent baseline report | `reports/model_cards/independent_verification_report.json` |
| Normal Phase 3 report | `reports/trust_reports/traffic_rf_v1_phase3_trust_report.json` |
| Evasive Phase 3 report | `reports/trust_reports/traffic_rf_v1_evasion_probe_phase3_trust_report.json` |

---

## 13. Deep Assessment Levels

When a model scan starts, Credora now reports assessment progress by level:

| Level | Assessment | What it checks |
|---|---|---|
| Level 0 | Intake | Reads metadata and prepares scan inputs |
| Level 1 | Integrity | Checks model format, SHA-256 hash, signature metadata, and artifact size |
| Level 2 | Supply Chain | Reviews dependency/package risk |
| Level 3 | Classifier Performance | Runs predictions and calculates observed evaluation accuracy, precision, recall, F1, and confusion matrix |
| Level 4 | Robustness | Perturbs flow features and checks prediction stability |
| Level 5 | Data Drift | Compares current traffic features against baseline training data |
| Level 6 | Explainability | Finds which flow features drive decisions |
| Level 7 | Leakage and Generalization | Checks holdout overlap and train/test performance gaps |
| Level 8 | Privacy Risk | Estimates memorization and membership-inference risk |
| Level 9 | Behavior Analysis | Checks confidence, weak classes, suspicious-class recall, class confusion, and feature reliance |
| Level 10 | Model Risk | Reviews unsafe serialization, metadata completeness, and deployment risk |
| Level 11 | Adversarial Validation | Runs timing jitter, sensitive-flow evasion, and sensor feature-dropout scenarios |
| Level 12 | Runtime Integrity | Verifies the deployed artifact hash and signature baseline |
| Level 13 | Security Gate | Applies non-negotiable signature, integrity, dependency, model-risk, adversarial, and sensitive-recall checks |
| Level 14 | Trust Scoring | Only after the Security Gate passes, combines performance, robustness, drift, dependency, privacy, and explainability evidence |
| Level 15 | Trust Drift | Compares an issued Trust Score against previous scans |
| Level 16 | Deployment Gate | Applies release policy after both the Security Gate and Trust Score are available |
| Level 17 | Threat Model and Final Report | Maps measured controls to threats and writes the deployment decision, tailored fixes, JSON report, and DOCX report |

Every new report also stores a persistent `analysis_trace`. Each trace record explains the method used, exact measured evidence, module conclusion, score, status, and detected issue names. The dashboard shows these records under **Traffic Classifier -> Deep Assessment Trace**, so the reasoning remains visible after the live progress display finishes.

Corrective actions are generated from the current report evidence, not selected from a recommendation checkbox. Each `remediation_plan` item contains a priority, evidence, diagnosis, required change, and measurable retest condition. For example, a `Suspicious -> VPN` confusion names the affected classes and observed flow count, drift remediation names the highest-PSI features, and adversarial remediation names the actual worst-case scenario. The legitimate and evasive model reports therefore receive different corrective plans.

---

## 14. Phase 3 Production Validation

Phase 3 is complete for the project scope. The scanner now covers pre-deployment assessment and post-deployment operational monitoring.

Unsigned `.joblib`, `.pkl`, and `.onnx` assessments fail the signature Security Gate but still display an assessment Trust Score, capped by the existing unsigned-artifact policy. A failed critical gate always blocks deployment independently of that score. The signed `.credora` packaging workflow verifies an external Ed25519 signature and artifact hashes; signatures alone do not override any other critical failure.

Classifier metrics are observations from the uploaded evaluation dataset. Even when observed evaluation accuracy is `1.0`, Credora does not present that result as guaranteed production accuracy; robustness, adversarial safety, drift, leakage, privacy, runtime integrity, and the Security Gate remain separate evidence.

Each generated report includes a threat model covering protected assets, threat actors, attack surfaces, trust boundaries, threat scenarios, control mappings, security assumptions, out-of-scope threats, and residual risk. Threat status is derived from the existing scan evidence rather than from a second synthetic assessment.

The real-model evasive validation profile scores `62.03/100` and is **blocked**. It produces `0.0` recall for `Suspicious`, confuses all 75 suspicious flows as `VPN`, detects high drift across all eight model features, and fails five production gate checks. This proves the scanner produces materially different evidence and fixes when model behavior becomes unsafe.

Completed Phase 3 operational milestones:

- continuous scheduled runtime hash monitoring with persisted evidence;
- captured-network flow ingestion from Zeek and CICFlowMeter;
- rolling production drift windows with deduplicated, acknowledgeable alerts;
- Ed25519-signed, hash-verified model packages using an external trust key;
- API endpoints and dashboard views for operational evidence;
- containerized API/dashboard deployment;
- CI execution of all tests, the real model release gate, and the container build.

Phase 4 is now implemented for signed final trust reports and trusted report-signer verification. Credora can generate Ed25519 report-signing keys, attach a `report_signature` block to the final JSON trust report, verify that report independently from CMD, and show whether the report matches an active trusted signer in the dashboard. See `docs/PHASE4_RUNBOOK.md` for the exact commands.

---

## 15. Real-Time Environment Note

The included real-time probe is a live simulation using encrypted-flow metadata. For captured traffic, use the Phase 3 Zeek/CICFlowMeter ingestion workflow; Credora consumes collector output and does not sniff or decrypt packets itself.

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

---

## 16. Phase 15: Sequence Work

### Sequence-based deep learning support

**Status: Implemented for the safe ONNX/NPZ sequence track.** The original phase excluded raw captures and GPU execution. Subsequent bounded extensions now support classic PCAP with explicit labels, optional ONNX CUDA execution and approved weights-only imports; see [Extended assessment inputs](docs/EXTENDED_INPUTS.md). The original phase contract below describes its baseline scope, not the limits of these later extensions.

Phase 15 adds ONNX-exported models that take raw packet-byte or token sequences (1D-CNN, LSTM, or small transformers) instead of flat tabular columns. It assumes the work from items 1-14 is complete, especially:

- item 14.1, the `ModelBackend` abstraction, which this plan extends;
- item 5, the stage-aware expected-module sets, which this plan makes input-type-aware;
- item 6, multi-trial perturbation, which the byte-level attacks reuse; and
- item 7, the single sensitive-label taxonomy, which the sequence adversarial module reads.

This is a substantial second project on top of the tabular workflow. The completed scope keeps sequence inputs bounded to safe, pre-tokenized `.npz` data and documents unsupported raw PCAP ingestion rather than accepting it implicitly.

**Backward compatibility is mandatory:** all existing tabular scans and the complete items 1-14 test suite must pass unmodified before Phase 15 is considered complete.

The ONNX-only policy makes two changes to the earlier deep-learning plan:

- Captum and Integrated Gradients require a live PyTorch model. Since uploads are ONNX-only, sequence explainability uses occlusion instead (15.7).
- Expected-module sets must vary by input type, or sequence scans would be penalized for modules that do not apply (15.11).

The expected runtime dependency remains the ONNX stack from item 14: `onnxruntime` and `onnx`. `dpkt` is needed only if raw pcaps are accepted (15.3). `torch` belongs in `requirements-dev.txt` only, for building the test fixture.

### 15.1 Fix ONNX safety checks first

**Files:** `core/config.py` near `verify_model_file_type`, or a new `core/onnx_safety.py`

`onnx.checker.check_model()` validates structure, not safety. Before creating any `InferenceSession`, reject these attack surfaces:

- external tensor data, because an initializer can point to a file path through `location` and cause a path-traversal read;
- custom operator domains outside the standard allowed sets; and
- custom opset domains outside the standard allowed sets.

The safety validator must load with `load_external_data=False`, reject external initializers, and allow only the empty domain, `ai.onnx`, and `ai.onnx.ml`. Call it from the existing `OnnxBackend` and the future sequence backend. Back-port the same check to the tabular ONNX path from item 14.6.

### 15.2 Define the sequence input contract

**Files:** metadata schema, `scripts/run_phase1_scan.py`, and `api/main.py`

Require these metadata fields when `input_type == "sequence"`:

- `input_type`: `"tabular"` by default, or `"sequence"`;
- `max_sequence_length`: integer matching the ONNX input shape;
- `class_labels`: ordered list mapping output indexes to labels;
- `sequence_dtype`: `"int64"` for token or byte ids, or `"float32"` for normalized bytes; and
- `vocab_size`: integer used to validate that no id exceeds the vocabulary.

Validate the ONNX graph input shape and dtype against the metadata at load time. Fail clearly on mismatch and never coerce silently.

### 15.3 Build the dataset loader, `.npz` first and pcap second

**New file:** `core/sequence_data.py`

The primary path is a pre-tokenized `.npz` containing `X` with shape `n x max_sequence_length` and `y` labels:

```python
data = np.load(path, allow_pickle=False)
X, y = data["X"], data["y"]
```

`allow_pickle=False` is mandatory because enabling pickling creates the same remote-code-execution class that the existing upload controls are designed to prevent. Add a test that a pickled-object `.npz` is rejected.

Validate dtype, NaN absence, vocabulary bounds, `len(X) == len(y)`, a row cap such as 200,000 rows, and a file-size cap.

The secondary raw `.pcap` path is optional and should be attempted only if time allows:

- parse with `dpkt` in an isolated subprocess with a timeout, reusing the preflight pattern from `core/model_loading.py`;
- cap packets per file and bytes per packet because pcap parsers are a denial-of-service surface;
- mask or strip Ethernet and IP headers so addresses do not become model features;
- truncate and pad each packet to `max_sequence_length`;
- read labels from a companion CSV because pcaps do not contain labels; and
- store uploads under `resolve_user_data_path`, then delete raw pcaps after tokenization because they may contain payloads and addresses.

The recommended first release is `.npz`-only. It is the safer path and covers the complete testable workflow.

### 15.4 Extend the backend abstraction

**File:** `core/model_backend.py`

Add `SequenceOnnxBackend(ModelBackend)` with the same `predict` and `predict_proba` interface, but accept a NumPy array instead of a DataFrame.

- Apply the 15.1 safety validation in the constructor.
- Use batched inference, for example 256 rows per batch, to bound memory.
- Apply softmax to raw logits when necessary so `predict_proba` always returns a probability matrix. Detect this from row sums.
- Return `None` from `feature_importance()`, as the tabular ONNX backend does.
- Reuse the subprocess-isolation pattern already implemented in `core/model_loading.py` for item 1 through the shared process-isolation helper; do not create a second independent sandboxing mechanism.

Update `load_model_backend(path, metadata)` to select this backend when `input_type == "sequence"`, and update its call sites to pass metadata.

### 15.5 Branch classifier evaluation by input type

**File:** `modules/phase1_foundation/m8_etc_classifier/evaluate.py`

For sequence metadata, load data through `core/sequence_data.py`; otherwise keep the existing CSV path. Preserve the existing output contract: accuracy, precision, recall, F1, confusion matrix, weak classes, and confusion pairs. The trust aggregator and report schema should not need to know which input path produced the metrics.

Apply the same branch in `modules/phase2_deep_trust/m8_behavior_analysis/behavior.py`, since confidence statistics and per-class weakness require only `predict` and `predict_proba`.

### 15.6 Add sequence robustness and adversarial scenarios

**New file:** `modules/phase3_operations/m4_adversarial_validation/sequence_adversarial.py`

Call the sequence module from `adversarial.py` and `robustness.py` when `input_type == "sequence"`. Tabular perturbations do not transfer to sequences. Add:

- random byte noise, replacing a small percentage of positions with random ids;
- truncation, zeroing the tail after position `k`;
- padding injection at random offsets;
- position shift or block reordering to simulate segmentation differences; and
- packet dropping for sequences representing several packets.

Reuse the multi-trial loop from item 6 and score the worst-case percentile. Use `get_sensitive_label_taxonomy()` from item 7 for sensitive-class recall. Keep the scoring logic unchanged and state clearly in findings that these are semantic-agnostic perturbations that do not guarantee a valid packet.

### 15.7 Replace feature explainability with occlusion saliency

**File:** `modules/phase2_deep_trust/m5_explainability/explain.py`

For sequence models, skip SHAP and `feature_importances_`. Use sliding-window occlusion with `predict_proba`:

1. Select representative flows, for example 20 samples stratified by class.
2. For each window position, use a window of 8-16 tokens and replace it with the pad id.
3. Define saliency as the drop in the originally predicted class probability.
4. Aggregate a per-position mean saliency curve for each class.

The output changes to records such as `{"class", "position_start", "position_end", "saliency"}` instead of `{"feature", "importance"}`. Document the difference in the report. Add a finding when saliency concentrates in the first few positions, which can indicate shortcut learning from header bytes rather than payload behavior.

### 15.8 Adapt drift detection to sequence aggregates

**File:** `modules/phase2_deep_trust/m4_data_drift/drift.py`

Because sequences do not have ordinary per-column distributions, compute these aggregates for each sequence:

- non-pad length;
- byte or token entropy;
- fraction of zero or pad ids; and
- a coarse token-id histogram, such as 16 bins.

Run the existing PSI function on each aggregate against a training `.npz` baseline in the same format. Report which aggregate drifted. Embedding-space MMD remains a stretch goal and is not part of this phase.

### 15.9 Adapt leakage and privacy modules

**Files:** `modules/phase2_deep_trust/m10_dataset_leakage/leakage.py` and `modules/phase2_deep_trust/m11_privacy_risk/privacy.py`

- For leakage, hash each sequence row with `hashlib.sha256(row.tobytes())` and compare train and test sets, following the tabular row-hash approach.
- For privacy risk, reuse the train-versus-holdout confidence comparison through `predict_proba`; only the sequence data loader needs to change.

### 15.10 Mark modules that do not apply to ONNX

**Files:** `scripts/run_phase1_scan.py`, `modules/phase1_foundation/m2_dependency_scanner/scanner.py`, and `modules/phase2_deep_trust/m6_model_risk/risk.py`

- Dependency scanning audits a `requirements.txt`. ONNX models do not ship one, so a missing requirements file must not be reported as a defect for an ONNX scan.
- Add a `not_applicable` status to `ModuleResult`, distinct from missing or failed.
- Do not raise pickle or joblib findings for ONNX. Surface ONNX-specific facts instead, including opset version, graph node count, input shape, and output shape.
- Update the Security Gate and Deployment Gate so an explicitly approved `not_applicable` check is satisfied rather than treated as missing. Checks that are applicable but absent or failed must continue to fail closed.

### 15.11 Make expected-module sets input-type-aware

**File:** `modules/phase1_foundation/m11_trust_score/aggregator.py`

Item 5 defines fixed preliminary and final expected sets. Build the expected set per scan by removing modules marked `not_applicable` for that input type, and renormalize weights over applicable modules only.

Regression tests must confirm that:

- a complete sequence scan scores the same as an equivalent complete tabular scan, with no accidental penalty; and
- a sequence scan that genuinely lacks an applicable module is still penalized.
- The deployment gate must use the same input-aware applicability decision, especially for sensitive recall and adversarial checks.
- Trust Drift lineage must include `input_type` alongside `(owner_id, model_name)` so tabular and sequence scans cannot be compared as one history.

### 15.12 Pre-scan compatibility validation

Before a full scan is queued, validate the ONNX graph input shape and dtype against metadata and the NPZ dataset. Surface a direct error such as `Model expects sequence length 256, but metadata declares 128` instead of waiting for a later assessment level.

### 15.13 Add resource and safety limits

**Files:** `core/config.py`, `api/main.py`, and `scripts/run_phase1_scan.py`

- Keep the existing tabular cap and add configurable sequence model and dataset caps, for example 100 MB by default and up to approximately 500 MB for ET-BERT-scale exports.
- Add per-module timeouts with a clear `timed out` finding. Cap sampled flows and trials because occlusion multiplies inference cost.
- Run `InferenceSession` creation and inference in an isolated subprocess with a timeout, matching item 1. ONNX Runtime is native code parsing an untrusted graph, so 15.1 reduces but does not eliminate the risk.
- Use CPU-only execution. GPU handling is outside this phase.

### 15.14 Update report, dashboard, and admin surfaces

**Files:** `core/report_schema.py`, `dashboard/app.py` or its page files, and admin endpoints

- Add top-level `input_type` and a `saliency` section to the report. Report signing remains unaffected because the new fields are inside the signed JSON.
- Add an input-type selector to the upload form. When sequence is selected, reveal the metadata fields from 15.2 and accept `.npz` files.
- All new sequence upload and scan endpoints must use the same `get_current_user`, rate-limiting, owner-scoping, and API-key protections as existing tabular upload and scan endpoints. No unauthenticated or unscoped parallel route is allowed.
- Add a simple saliency view, such as a bar or line plot by position and class, rather than a full heatmap.
- Deployment-policy thresholds are global today. The simplest policy is to share them with sequence models and document that decision.

### 15.15 Build test models and fixtures

**New script:** `scripts/build_test_sequence_model.py` (development-only `torch` dependency)

Generate synthetic sequences with class-specific byte motifs at varied offsets and noise. Use 4-5 classes, length 128, and a few thousand rows. Train a small 1D-CNN in PyTorch, export it to ONNX with opset 15 or lower and no external data, and save:

- `seq_demo_strong.onnx`;
- `seq_demo_test.npz`;
- `seq_demo_train.npz`; and
- `metadata.json`.

Also build a deliberately weak variant, such as one trained for too few epochs or with heavy class imbalance, to confirm that the score discriminates. Commit the small ONNX and `.npz` fixtures so CI does not need `torch`; regeneration remains a manual development step. Never run ET-BERT-scale models in CI.

### 15.16 Add tests

**New files:** `tests/test_sequence_backend.py`, `tests/test_onnx_safety.py`, and `tests/test_sequence_data.py`

Tests must cover:

- rejection of external-data initializers and custom ONNX domains, plus acceptance of a valid model;
- rejection of pickled-object `.npz` files, out-of-vocabulary ids, and length mismatches;
- fixture predictions, probability sums, and loud failure for metadata shape or dtype mismatches;
- a full scan producing a real trust score without raising;
- a weak fixture scoring below the strong fixture;
- the 15.11 scoring regressions; and
- occlusion saliency peaking near a known discriminating motif position.

### 15.17 Update documentation and copy

**Files:** README and the login-page panel

- Split supported models into tabular and sequence tracks.
- State which modules apply to each track and explain that sequence reports use saliency instead of feature importance.
- Document that raw `.pt`, `.pth`, and TensorFlow checkpoints remain unsupported by design and explain why.
- Update the login-page format line only after sequence support actually ships.

### Corrected implementation order

1. Backward-compatibility baseline and regression suite.
2. ONNX safety, sequence metadata, NPZ loading, and pre-scan compatibility validation.
3. Sequence backend and classifier/behavior evaluation.
4. `not_applicable` handling, input-aware scoring and gates, and Trust Drift lineage migration.
5. Resource limits and shared subprocess isolation.
6. Core tests for items 1-5 only.
7. Strong and weak sequence fixtures.
8. Core dashboard/report view for metrics, Trust Score, input type, and explicit `not_applicable` results.
9. Sequence adversarial validation, sequence drift, sequence leakage/privacy, and occlusion saliency.
10. Enrichment UI pass wiring the saliency graph and drift evidence created in step 9.
11. Final API/dashboard/report polish, documentation, signed-report verification, and the complete regression suite.

The dashboard work is intentionally split: the first pass exposes only results that already exist; the enrichment pass follows the sequence-specific modules so it is not built twice.

The initial test pass covers steps 1-6 only. Tests for adversarial validation, drift, leakage/privacy, and saliency are added incrementally beside those modules, and the final step runs the combined suite.

### Suggested reduced scope

If time is limited, implement 15.1, 15.2, 15.3 with `.npz` only, 15.4, 15.5, 15.10, 15.11, 15.12, 15.15, and 15.16. This provides end-to-end ONNX sequence evaluation with real metrics, a correct trust score, and safety checks. Mark robustness (15.6), saliency (15.7), and sequence drift (15.8) as `not_applicable` for sequence models rather than silently omitting them. Every reduced-scope report must state which sequence capabilities are not yet supported. Add those later in the order 15.6, 15.8, 15.7, because 15.7 is the largest task.

**Completion criterion met for the implemented scope:** upload a bounded ONNX sequence classifier with `input_type: "sequence"` and a tokenized `.npz` dataset, then produce a trust report with real accuracy metrics, sequence robustness and adversarial results, sequence-aggregate drift, leakage/privacy evidence, and position-level saliency. A malicious ONNX file or malicious `.npz` must not execute code or read files outside the intended directories. All existing tabular scans and their tests continue to pass unchanged. Raw PCAP parsing, GPU execution, and raw PyTorch/TensorFlow checkpoints remain outside this phase.




