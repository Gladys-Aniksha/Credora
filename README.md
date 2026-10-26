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

### Documentation map and current scope

- [Simple project guide](docs/Credora_Simple_Project_Guide.docx): plain-language explanations of each page, controls, charts, assessment modules and common errors. This is a learning guide, not a signed assessment report.
- [Extended assessment inputs](docs/EXTENDED_INPUTS.md): exact ONNX, optional GPU and offline PCAP contracts and limits.
- [Security hardening verification](docs/SECURITY_HARDENING_VERIFICATION.md): dated test results and security boundaries. The four hardening phases are separate from the older numbered feature roadmap below.
- [Model release runbook](docs/PHASE3_RUNBOOK.md) and [report signing runbook](docs/PHASE4_RUNBOOK.md): operational release and signature commands.

Current runtime scope is tabular sklearn/ONNX and compatible sequence ONNX. Native PyTorch/TensorFlow checkpoint import, uploaded Python conversion and the earlier Docker/native-import wiring were removed in the scope cut. Export compatible, self-contained ONNX models in a separate trusted development environment. CPU inference is the default; GPU selection remains optional and is not a guarantee of all-node GPU execution.

## Dashboard Features and Result Interpretation

The dashboard uses the shared Credora branding and theme, icon navigation with hover names, and responsive layouts. Login and registration use an equal-column desktop layout, password confirmation on registration and explicit submit buttons. Role and account context determine which pages and records are visible.

| Page | Current purpose and features |
|---|---|
| Overview | Deployment readiness, Trust Score, model integrity, dependency risk, assurance tier, saved-score trends, model summary, recent assessments and alerts. |
| Model Registry | Registered model metadata, the active model summary and saved scan history. Select the intended model/assessment before interpreting results. |
| Upload Model | Own files or demo models; tabular/sequence input selection; prepared datasets or supported offline PCAP plus labels; ONNX device selection; compatibility checks and assessment progress. |
| Traffic Classifier | Expandable assessment trace; accuracy, precision, recall, F1 and confusion matrix; leakage/privacy and behavior evidence; class-specific results; adversarial scenarios and production gate checks. Sequence reports add occlusion saliency and sequence robustness/drift evidence. |
| Trust Score | Measured versus policy-limited score evidence, assurance display, failed security checks and individual module health. |
| Threat Model | Protected assets, actors, attack surfaces, trust boundaries, control evidence, initial/residual risks, assumptions and scope limits. Not-assessed threats are shown separately, not treated as verified safe. |
| Trust Drift | Current-versus-previous module comparison, saved scores by date, feature/sequence aggregate PSI and available captured-production drift windows. |
| Reports | Checked JSON/DOCX downloads, report signature verification, execution/input provenance, assessment trace and evidence-based remediation plans. |
| Alerts | Severity filters, findings and recommended fixes, plus open production/security monitoring alerts. Acknowledging an alert records review; it does not fix the problem. |
| Settings | Profile/password changes, informational-finding and upload/report preferences, confirmed deletion of owned records and runtime integrity history. |
| Admin | Role-restricted user management, platform scans, release policy/weights, sensitive labels, trusted public signers, justified review decisions and security audit logs. |

Completed upload assessment activity is retained in the current session across page navigation; a new assessment replaces that activity. Saved report snapshots and their `analysis_trace` provide durable evidence independently of the transient progress display. A browser refresh/session loss can reset upload widgets; use the registry and saved assessment views rather than assuming the selected files remain in the form. Full selected filenames are also displayed in upload descriptions to reduce confusion between files named `metadata.json`.

### Scores are not interchangeable

- **Classifier accuracy/F1** describe predictions on the supplied evaluation data. `1.000` means a perfect result on that test, not a guarantee on future traffic or real attacks. Synthetic fixture categories are not automatically real-world threat classes.
- **Measured assessment score** combines applicable module results using configured weights and coverage. Unsigned raw-model assessments are capped at **70** for the issued Trust Score; a stronger measured score can therefore still display 70. Missing applicable modules and failed security gates remain visible.
- **Deployment approval** is separate. A failed mandatory Security Gate blocks release regardless of performance or tier. Default production minimum trust/classifier scores are 85; the dashboard's 70 review indicator is not the production approval threshold.
- **Dependency Risk** reverses the dependency assessment score (`100 - score`), so lower is better. A short success label is not a guarantee that every dependency is safe.
- **Assurance tiers** are A: 85+, B: 70 to below 85, C: 50 to below 70, D: below 50. The ring is a score visualization, not percentages of models in each tier.
- **Assessment comparison** plots modules, not time. Its completed-check count (for example, 12/12) counts available results, not passed checks. The separate dated history chart connects saved scans; it is not continuous live monitoring. Capped final scores can hide changing module results.
- **Sequence saliency** masks input windows and measures the probability drop for the original predicted class; it is not a fall in overall accuracy. Robustness scenarios are controlled, semantic-agnostic perturbations, not proof against every attack.
- **PSI drift** compares distributions: below 0.10 is low, 0.10 to below 0.25 medium, and 0.25+ high in the current implementation. Low or zero PSI does not prove identical datasets or accurate predictions.
- **Runtime integrity** must be interpreted with its hash and signature details. The current `changed` label can also reflect missing signature evidence; the label alone does not establish tampering. Critical finding counts can include related consequences of one underlying issue.

### Captured flow ingestion is a separate optional workflow

The Traffic Classifier page accepts supported Zeek `conn.log` or CICFlowMeter CSV records. Collector format chooses the reader; Auto-detect is the starting option. Window rows (default 250) means records per batch, not seconds. Ingest and monitor flows converts supported records and stores drift-window results for the Trust Drift page. This workflow needs compatible tabular features and baseline data; it is not the sequence NPZ uploader and does not automatically support an arbitrary model schema. It does not sniff live packets, retrain the model or remove a release block. No production windows means none have been analyzed, not that production traffic has passed.

## Matching Files for a First Assessment

Always take the model, test dataset and metadata from the **same folder**. Do not mix the DoH tabular model with the sequence NPZ files or change metadata fields just to bypass validation.

| Example | Model | Test data | Metadata | Upload input type |
|---|---|---|---|---|
| Trained sequence strong | `data/trained_sequence_test_kit/credora_sequence_strong/credora_sequence_strong.onnx` | `test.npz` in that folder | `metadata.json` in that folder | Sequence tokens/bytes |
| Trained sequence weak | `data/trained_sequence_test_kit/credora_sequence_weak/credora_sequence_weak.onnx` | `test.npz` in that folder | `metadata.json` in that folder | Sequence tokens/bytes |
| Small sequence fixture | `data/sequence_test_kit/credora_sequence_strong/credora_sequence_strong.onnx` | `test.npz` in that folder | `metadata.json` in that folder | Sequence tokens/bytes |
| DoH tabular strong | `data/doh_onnx_test_kit/credora_doh_strong/credora_doh_strong.onnx` | `test.csv` in that folder | `metadata.json` in that folder | Tabular flow features |

For these prepared-data examples, select **Upload files**, the matching input type, **Prepared dataset**, and **CPU**. Supply dependency requirements describing the actual model environment when available; sequence ONNX requirements are optional under the documented applicability policy. Do not attach an unrelated manifest just to fill a field. Keep referenced `train.npz`/`train.csv` baselines available under the supplied fixture layout for drift, leakage and privacy checks.

The trained sequence fixtures use 128 positions, while the small sequence fixtures use 32. The DoH strong tabular graph consumes 21 feature columns. Compatibility validation checks graph shape/dtype, metadata and dataset before the full scan. Mismatch errors include the actual graph input details; use them to choose the correct matching set instead of truncating, padding or relabeling incompatible evidence. These public fixtures are for evaluation/regression demonstrations, not certified production models.

## Multi-User Access and Data Isolation

Credora now supports username/password login for the dashboard and bearer-token authentication for the API. Each user owns their uploaded files, model registry entries, scan history, reports, drift windows, runtime integrity records, and alerts. Uploaders only see their own data; reviewers and admins can enable all-user visibility for review workflows.

`CREDORA_API_KEY` is required in every environment; Credora will refuse to start if it is missing. For local development, generate separate random values with `python -c "import secrets; print(secrets.token_urlsafe(48))"`, then place them in a gitignored `.env` file:

```dotenv
CREDORA_API_KEY=<generated service API key>
CREDORA_JWT_SECRET=<different generated JWT secret>
CREDORA_MODEL_ENCRYPTION_KEY=<URL-safe base64 encoding of 32 random bytes>
```

Never commit the `.env` file or reuse these values outside their intended deployment.

## Artifact Integrity and Report Evidence

The integrity workflow records an owner-scoped, server-side SHA-256 baseline for each model artifact path. API model/package uploads and dashboard model uploads establish that identity before assessment. Reusing a registered path verifies the original baseline rather than replacing it with the file's current hash. Scans check the source artifact before loading or extracting it, check the evaluated model before inference, and recheck before report publication. Signed packages retain bindings for both the source package and the extracted model. A changed or unavailable artifact fails closed; it cannot silently become the new trusted baseline.

Reports carry a path-free `model_artifact` binding (`id`, `owner_id`, `sha256`, with a source binding for packaged models). Access checks resolve this against the server registry and model-verification evidence; a caller-supplied hash alone is insufficient. Latest-report and report-signature API access reject integrity/evidence failures with HTTP 409. Dashboard downloads validate during page rendering and again when the deferred download is requested. DOCX downloads regenerate from the checked report snapshot rather than serving a cached document as trusted evidence. Legacy reports without an unambiguous owner-scoped registration and verification hash cannot be exported as verified snapshots.

Every generated finding must cite its actual containing `module` and a `metric` path that resolves to recorded evidence: `score`, `status`, or a dotted `details` path, including list indices. Report serialization/export and file-signing boundaries reject missing, misattributed or unresolved citations and duplicate module identities. This establishes **structural traceability**, not mathematical proof that a measurement is correct or semantic proof that its prose interpretation follows from the cited value.

The dashboard requires Streamlit 1.59.2 or newer, the tested baseline for deferred download callbacks. Installing `requirements.txt` enforces that minimum; report downloads must not fall back to preparing unchecked bytes at page-render time.

These controls assume the server, registry database and signing keys remain trustworthy. They do not protect against an attacker who can rewrite both an artifact and its server-side baseline, and file rechecks do not eliminate every concurrent replacement race. Protected storage and access controls are described below. Model/report signatures and deployment gates retain their existing, separate roles; passing an integrity check does not approve deployment.

If an artifact changes, restore the exact registered bytes or intentionally upload a new artifact identity and reassess it. Do not replace the recorded baseline to silence an integrity error. Focused workflow regressions are in `tests/test_phase2_integrity_workflow.py`; its valid scan uses real ONNX classifier inference with controlled non-classifier stages.

## Phase 3 Security Setup: Protected Model Storage

Set the required `CREDORA_MODEL_ENCRYPTION_KEY` in the application's runtime environment. There is no default key. Its value must be the URL-safe base64 encoding of **32 random bytes**. For a new deployment, generate it once:

```powershell
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode('ascii'))"
```

This command only generates compatible key material: stored artifacts use **AES-256-GCM**, not Fernet encryption. Keep the generated value outside the repository in protected secret storage, back it up securely, and supply the same key to the API, dashboard, command-line tools and inference workers. `.env.example` deliberately leaves its placeholder empty. Do not commit the key, put it in command-line arguments, or replace it on every startup. **Overwriting this key is not a rotation procedure**: existing encrypted artifacts need their original key. Losing that key prevents recovery of their model bytes.

A local `.env` containing the key is only a development convenience: it does not protect models from an attacker who can read that file too. Production must supply the key separately from the repository, model files and artifact backups, using protected runtime secret storage.

Uploaded models, extracted models and stored `.credora` packages use authenticated encrypted envelopes bound to their owner and storage path. A package archive contains model bytes and therefore needs the same protection as an extracted model. Loading decrypts model bytes in memory; protected artifacts must not be written to plaintext temporary files. Copying or renaming an encrypted artifact to another owner or path is not a supported migration. Integrity comparisons and signed package manifests continue to use the original plaintext SHA-256 and logical payload size, rather than ciphertext bytes or envelope overhead.

### Migrate existing registered artifacts

Managed plaintext model/package files under `data/uploads` are blocked by normal reads until explicitly migrated. Before resuming scans or report actions on an existing deployment, retain the existing registry and key backups and review the migration inventory. The default command only lists registered upload candidates; it does not encrypt files or certify that their hashes match:

```powershell
.\.venv\Scripts\python.exe scripts\encrypt_model_storage.py
```

To explicitly apply in-place encryption:

```powershell
.\.venv\Scripts\python.exe scripts\encrypt_model_storage.py --apply
```

The migration verifies original model bytes against their registered hashes before encrypting them in place. It must preserve those original identities and hashes; it must not adopt the current contents as a replacement baseline. If verification fails, restore the exact original artifact or upload a new identity and reassess it. Do not reset the registry to make migration pass. Run migration during an operator-controlled maintenance window without concurrent model uploads, scans or report actions.

An old model or package file without an original server registration cannot be automatically migrated: there is no trusted original hash to verify. The inventory flags unregistered `.onnx`, `.pkl`, `.joblib` and `.credora` files under `data/uploads` as `UNREGISTERED` and exits nonzero, including in dry-run mode; it does not create baselines for them. The operator must explicitly upload and reassess the intended original as a new identity, or securely clean up the obsolete unregistered copy. Do not create a baseline from an unknown file merely to make migration accept it. Source fixtures are excluded from migration.

### Access monitoring and protection limits

Application-mediated model reads are audited with the requesting identity and operation. `CREDORA_MODEL_ACCESS_DISTINCT_LIMIT` defaults to **20** distinct owner/canonical-model-path identities per actor, and `CREDORA_MODEL_ACCESS_WINDOW_SECONDS` defaults to **60** seconds. Source packages and extracted models count separately, as do new upload identities containing identical bytes. Purposes and owners do not give an actor separate budgets. Admitted attempts count even if later reads fail; denied requests do not consume additional slots. Unusually broad access is blocked before reading bytes and surfaced through the existing runtime alerts. This is a configurable, rule-based burst detector, not a learned anomaly classifier. Inspect the existing audit-log and alert views when investigating blocked access. This is not operating-system file-access auditing: direct filesystem reads bypass these application logs. These controls protect stored model confidentiality and make unusual application access visible; they do not add a public model inference endpoint.

The API buffers the complete request body in RAM under `CREDORA_MAX_UPLOAD_BYTES` (default 200 MiB), including multipart framing and all files, before parsing. Accepted multipart file parts remain in RAM rather than spooling plaintext models to temporary disk files. The direct ONNX file limit remains 50 MiB. Request buffering, multipart parsing, decryption and inference can hold several copies of a payload in memory, and concurrent requests multiply that cost; the per-request cap is not a process-wide memory ceiling. Set deployment concurrency and upload limits for the available RAM, and check any reverse proxy's buffering configuration separately.

Protection applies to application-managed uploaded/extracted models and packages. **Public repository fixtures intentionally remain plaintext source artifacts and are not protected secrets.** This feature is not general filesystem encryption: evaluation datasets, metadata and reports are outside its model-encryption scope. It does not protect against an attacker who also obtains the runtime encryption key or controls the running server. Keep the registry, key backups and runtime environment protected separately; model signatures, report signatures and deployment gates retain their own roles.

Encryption is not a model sandbox. Pickle/joblib inspection and the bounded deserialization preflight are defense-in-depth, not an operating-system security boundary or a guarantee that arbitrary Python model artifacts are safe. Prefer validated ONNX for untrusted model submissions and restrict Python-serialized artifacts to trusted producers.

## Security Verification

The scope-cut and security-hardening implementation now includes these controls:

| Control | Implemented behavior | Important boundary |
|---|---|---|
| Integrity re-verification | Original owner/path SHA-256 is checked before scans and report actions. | Registry integrity and trusted server operation remain assumptions. |
| Evidence-traceable reports | Every finding cites a real module and resolvable metric. | Traceability does not prove the measurement or prose interpretation is correct. |
| Encryption at rest | Uploaded/extracted models and uploaded packages use AES-256-GCM; loading uses in-memory plaintext. | A persistent runtime key and explicit migration of legacy uploads are required. |
| Access audit | Application model-read attempts, outcomes, actor, owner and purpose are recorded. | Direct filesystem access is not an application audit event. |
| Unusual-access detection | A persistent per-actor distinct-artifact window blocks excess access and creates alerts. | This is a configurable rule, not learned anomaly detection or a global memory limit. |

The commands, six historical UI/backend regressions, combined diff scope and
environment-specific limits are recorded in [the final verification report](docs/SECURITY_HARDENING_VERIFICATION.md).

## Local Setup

### Windows CMD quick start and configuration troubleshooting

Run from the project root. The following commands are for **Command Prompt (CMD)**, not PowerShell; replace the folder with your actual checkout location:

```cmd
cd /d "C:\path\to\Mini project"
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env
```

Only copy the example when creating a new `.env`; **do not overwrite an existing configuration or encryption key**. Fill the three required secrets with real, separately generated values. Generate authentication secrets with `secrets.token_urlsafe(48)` as above and generate the encryption key once using the command in **Phase 3 Security Setup: Protected Model Storage**. Keep that encryption key for all existing encrypted uploads.

```cmd
.venv\Scripts\python.exe -m streamlit run dashboard\app.py --server.port 8501
```

Open `http://localhost:8501/`. To start the API in a separate CMD window from the same configured project root:

```cmd
.venv\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

After saving changes to `.env`, stop the running dashboard/API with **Ctrl+C** and launch it again. Refreshing the browser alone does not reload an already running process's configuration. A variable previously set in the shell can take precedence over `.env`; remove a stale CMD override with `set CREDORA_MODEL_ENCRYPTION_KEY=` before restarting, if appropriate. Never print or share the actual key while diagnosing this.

If the key is still rejected, confirm the file is named `.env` (not `.env.txt`), is in this checkout's root, and contains `CREDORA_MODEL_ENCRYPTION_KEY` with URL-safe base64 encoding of exactly 32 bytes. Do not generate a replacement key to fix an existing encrypted deployment. Check legacy migration requirements before using old uploads. Keep browser zoom at its normal **Ctrl+0** setting before judging dashboard sizing.

Fresh verification commands for CMD are:

```cmd
.venv\Scripts\python.exe -m pytest -q -rs
.venv\Scripts\ruff.exe check --select E4,E7,E9,F --ignore E402 core modules scripts api dashboard tests
.venv\Scripts\mypy.exe --ignore-missing-imports --explicit-package-bases --disable-error-code=arg-type --disable-error-code=var-annotated --disable-error-code=misc core modules scripts api
.venv\Scripts\bandit.exe -q -lll -r core modules scripts api dashboard
```

For local development only, Credora creates a bootstrap administrator when the registry has no users. The default username is `admin` and the default password is `credora-admin`. Override these defaults before shared or deployed use by setting `CREDORA_BOOTSTRAP_ADMIN`, `CREDORA_BOOTSTRAP_EMAIL`, and `CREDORA_BOOTSTRAP_PASSWORD` in the same gitignored `.env` file or shell environment, then run:

```powershell
.\.venv\Scripts\python.exe scripts\migrate_add_users.py --show-users
```

The auth scheme assumes TLS when deployed beyond localhost. A JWT bearer token over plain HTTP should be treated as exposed.

## Supported Model Formats

Credora supports these model and evaluation tracks:

- **Tabular models:** scikit-learn-compatible `.joblib` and `.pkl` artifacts use pickle allow-list inspection and an isolated deserialization preflight. ONNX `.onnx` tabular models use structural and safety validation, with labeled CSV evaluation data.
- **Sequence models:** compatible ONNX classifiers use labeled NPZ files containing `X` and `y`, explicit shape/dtype/vocabulary metadata, and bounded isolated inference. Object/pickled NPZ arrays, external ONNX tensor data and custom operator domains are rejected. CPU is the default for both ONNX tracks.
- **Signed packages:** `.credora` packages provide externally verified signatures and artifact hashes; all other security and deployment gates still apply.

**Optional GPU execution:** ONNX metadata accepts `execution_device: "cpu"`, `"auto"` or `"cuda"`. CPU remains the default; CUDA is opt-in through metadata or the upload/CLI device selector. Explicit CUDA fails if unavailable unless `execution_fallback: "cpu"` is supplied; Auto permits CPU fallback by default. Available/configured/registered providers and sampled node execution are reported separately. CPU graph-node fallback remains possible and `strict_gpu_guarantee` is always `False`; selecting CUDA does not prove every node ran on GPU. GPU hardware execution has not been verified here.

**Offline PCAP evaluation:** the converter accepts classic PCAP 2.4 only, either endian order, microsecond/nanosecond timestamps, Ethernet linktype 1 without flags, at most two VLAN tags, and IPv4/IPv6 TCP/UDP. IPv6 option/routing/AH chains are limited to eight headers. IPv4/IPv6 fragments (including atomic IPv6 fragments), ESP in either IP version, jumbograms, pcapng, snaplen-truncated records, malformed lengths and decreasing global timestamps are rejected. Non-IP Ethernet and other IP protocols are skipped and counted; at least one supported flow is required. An explicit flow-label CSV and a matching versioned preprocessing schema are mandatory. This is offline conversion with resource limits, no TLS decryption, TCP reassembly or inferred labels.

Framework checkpoint/weights files and uploaded Python are not accepted. Export a compatible classifier to ONNX in your own development environment before uploading it. GPU opt-in preserves predictable CPU deployments and exposes hardware/fallback differences; narrow PCAP parsing bounds hostile input and makes feature semantics reproducible. Exporting a model does not establish its provenance, sign it or approve deployment.

ONNX uses the same assessment and deployment-gate workflow as sklearn models, with sequence-specific evidence where applicable. The API's direct ONNX upload limit is 50 MiB; the sequence backend also has separate configurable model/dataset limits, which do not override the API upload limit. Exact schemas, limits and operational requirements are in [Extended assessment inputs](docs/EXTENDED_INPUTS.md).

### Runtime and optional requirements

| Requirements file | Where it is needed |
|---|---|
| `requirements.txt` | Standard application deployment; includes CPU `onnxruntime`. No GPU runtime, framework checkpoint decoders or Torch installation is required for normal ONNX/sklearn scans. |
| `requirements-gpu.txt` | Optional dedicated NVIDIA GPU environment. Use `onnxruntime-gpu` **instead of** CPU `onnxruntime`, while retaining the other application dependencies. Do not install both distributions together or install this file over an unchanged CPU requirements installation. Compatible NVIDIA hardware, CUDA and cuDNN must also be available. |
| `requirements-dev.txt` | Development/static-analysis and sklearn export tooling. Framework exporters belong in separate development environments, not the main application runtime. |

See `.env.example` for configuration names. Run the API/dashboard as Python processes using the existing local setup commands; no image build or external model-conversion service is required.

### Bring your own ONNX export

Run export in a separate development environment with your trusted, trained model already loaded. Install only the framework/exporter dependencies you need there: PyTorch with ONNX/ONNX Script, TensorFlow with tf2onnx, or scikit-learn with skl2onnx. Framework training runtimes and additional exporters are not dependencies of the serving application.

These short examples illustrate API usage, not verified exports of your particular model. The sequence examples assume one float32 `[batch, 128]` input and one `[batch, classes]` logits output. Supply matching metadata with `input_type: "sequence"`, `sequence_dtype: "float32"`, `max_sequence_length: 128`, `vocab_size` and ordered `class_labels`, plus labeled NPZ evaluation data. Tabular exports must return labels first, with optional class probabilities second; a logits-only tabular graph needs an appropriate classifier wrapper before export.

**PyTorch sequence classifier**, using the documented [ONNX exporter](https://docs.pytorch.org/docs/stable/onnx.html):

```python
import torch

model = trained_torch_model.cpu().eval()
example = torch.randn(2, 128, dtype=torch.float32)
torch.onnx.export(
    model, (example,), "sequence.onnx",
    input_names=["sequence"], output_names=["logits"],
    dynamo=True, dynamic_shapes=({0: torch.export.Dim("batch")},),
    opset_version=18, external_data=False,
)
```

**TensorFlow/Keras sequence classifier**, using [tf2onnx's `from_keras` API](https://github.com/onnx/tensorflow-onnx/blob/main/README.md#from_keras-tf-20-and-newer):

```python
import tensorflow as tf
import tf2onnx

signature = (tf.TensorSpec((None, 128), tf.float32, name="sequence"),)
tf2onnx.convert.from_keras(
    trained_keras_model, input_signature=signature,
    opset=18, large_model=False, output_path="sequence.onnx",
)
```

Choose compatible TensorFlow/Keras/tf2onnx versions in that export environment; support for one version combination does not establish support for every Keras release.

**scikit-learn tabular classifier**, using [skl2onnx's conversion API](https://onnx.ai/sklearn-onnx/auto_tutorial/plot_gconverting.html):

```python
import numpy as np
from skl2onnx import to_onnx

sample = np.asarray(training_features[:1], dtype=np.float32)
graph = to_onnx(
    fitted_classifier, sample, options={"zipmap": False}, target_opset=18,
)
with open("classifier.onnx", "wb") as stream:
    stream.write(graph.SerializeToString())
```

Preserve training preprocessing, feature order, shapes, dtypes and class-label order. Use a dynamic batch axis for bounded sequence batches. Upload a self-contained `.onnx` file with embedded tensors: external tensor files and custom operator/opset domains are rejected. Unsupported operators, converter limitations or incompatible input/output contracts can prevent an otherwise valid export from working in Credora; there is no guarantee of compatibility with every framework or model. Validate native-versus-ONNX prediction parity in the export environment and then run Credora's compatibility checks and evaluation. Opset 18 here is an example target, not a promise that every operator is supported.

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
| `Phase 15 sequence track` | ONNX sequence safety, NPZ evaluation, input-aware scoring, sequence evidence, robustness, and adversarial validation | Implemented for bounded ONNX + NPZ inputs; bounded labeled classic-PCAP conversion is available through the extended input path | Implemented |

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
| Deployment | Python API/dashboard processes; environment configuration and TLS for shared deployments |

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
- CI execution of tests and the model release gate.

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

**Historical implementation notes:** the numbered contract and imperative wording below preserve the original sequence development plan. They are not a current unfinished-task list. For current setup, matching inputs and delivered behavior use the sections at the top of this README and `docs/EXTENDED_INPUTS.md`. For dated test outcomes use `docs/SECURITY_HARDENING_VERIFICATION.md`; do not treat an old successful run as a fresh verification of every later edit.

### Sequence-based deep learning support

**Status: Implemented for the safe ONNX/NPZ sequence track.** Subsequent bounded extensions support classic PCAP with explicit labels and optional ONNX CUDA execution; see [Extended assessment inputs](docs/EXTENDED_INPUTS.md). Framework models must be exported to compatible ONNX before upload. The original phase contract below describes its baseline scope, not the limits of these later extensions.

Phase 15 adds ONNX-exported models that take raw packet-byte or token sequences (1D-CNN, LSTM, or small transformers) instead of flat tabular columns. It assumes the work from items 1-14 is complete, especially:

- item 14.1, the `ModelBackend` abstraction, which this plan extends;
- item 5, the stage-aware expected-module sets, which this plan makes input-type-aware;
- item 6, multi-trial perturbation, which the byte-level attacks reuse; and
- item 7, the single sensitive-label taxonomy, which the sequence adversarial module reads.

The sequence backend consumes bounded `.npz` data. The extended input path also converts explicitly labeled classic PCAP to this format under the precise `pcap_transport_bytes_v1` contract; it does not accept arbitrary capture formats or infer preprocessing.

**Backward compatibility is mandatory:** all existing tabular scans and the complete items 1-14 test suite must pass unmodified before Phase 15 is considered complete.

The ONNX-only policy makes two changes to the earlier deep-learning plan:

- Captum and Integrated Gradients require a live PyTorch model. Since sequence inference uses uploaded ONNX exports, sequence explainability uses occlusion instead (15.7).
- Expected-module sets must vary by input type, or sequence scans would be penalized for modules that do not apply (15.11).

The default runtime uses `onnxruntime` and `onnx`. Classic-PCAP parsing uses the Python standard library, with NumPy for sequence output; `dpkt` is not required. Optional trained-fixture generation uses CPU Torch installed directly in a separate development/export environment, not the production runtime. GPU dependencies are optional as described above.

### 15.1 Fix ONNX safety checks first

**Files:** `core/config.py` near `verify_model_file_type`, or a new `core/onnx_safety.py`

`onnx.checker.check_model()` validates structure, not safety. Before creating any `InferenceSession`, reject these attack surfaces:

- external tensor data, because an initializer can point to a file path through `location` and cause a path-traversal read;
- custom operator domains outside the standard allowed sets; and
- custom opset domains outside the standard allowed sets.

The safety validator loads with `load_external_data=False`, rejects external initializers, and allows only the empty domain, `ai.onnx`, and `ai.onnx.ml`. Both the tabular `OnnxBackend` and isolated sequence worker apply these checks.

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

The secondary `.pcap` path is implemented in `core/pcap_ingestion.py`, using bounded offline parsing rather than `dpkt`. It validates classic PCAP 2.4 Ethernet captures, requires explicit flow labels, and enforces packet/flow/byte limits. The sequence schema concatenates TCP/UDP payload bytes within each normalized bidirectional flow, maps byte to byte+1, then pads with zero; overlength flows are rejected rather than truncated. Addresses remain flow-matching keys, not sequence tokens. TCP retransmissions remain and there is no stream reassembly or TLS decryption. Raw capture retention must be managed by the operator; conversion does not promise automatic deletion. See [the current capture contract](docs/EXTENDED_INPUTS.md#offline-classic-pcap) before uploading.

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
- CPU remains the default. The extended execution policy permits optional CUDA with explicit fallback evidence and `strict_gpu_guarantee=False`; the same isolated sequence worker carries that policy.

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
- Framework checkpoint/weights files and uploaded Python are unsupported. Export compatible models to self-contained ONNX in a separate development environment before upload.
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

### Current sequence scope

Bounded ONNX sequence scans produce accuracy metrics, sequence robustness/adversarial results, aggregate drift, leakage/privacy evidence and occlusion saliency. Approved `not_applicable` results document actual non-applicability; implemented sequence modules are not described as future work. Hostile ONNX/NPZ inputs face structural, dtype, file-access and resource restrictions, but native runtime parsing and isolation still require maintained dependencies and hosts.

Classic-PCAP conversion and optional ONNX CUDA selection are implemented extensions to this baseline. Framework checkpoint/weights uploads are not supported; compatible external ONNX exports use the existing assessment path. The original implementation-order notes above describe the sequence baseline; use [Extended assessment inputs](docs/EXTENDED_INPUTS.md) for current operational constraints.




