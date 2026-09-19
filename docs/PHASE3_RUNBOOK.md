# Credora Phase 3 Runbook

Phase 3 turns the Credora prototype into a repeatable release workflow: local verification, signed model packages, CI release gating, dashboard evidence, and clean operational commands.

## One-command local verification

Run this from the project root:

```powershell
cd "C:\Users\glady\Mini project"
& ".venv\Scripts\python.exe" scripts\verify_project.py
```

This performs:

- Python compile check for `core`, `modules`, `scripts`, `api`, and `tests`;
- full pytest suite;
- sample Credora assessment with the bundled model and dataset;
- temporary Ed25519 key generation;
- signed `.credora` package creation;
- signed package release gate with `--minimum-score 85`.

Optional server smoke checks:

```powershell
& ".venv\Scripts\python.exe" scripts\verify_project.py --with-api --with-dashboard
```

## Signed package release path

Raw `.joblib` and `.pkl` files are still supported for local assessment, but Credora caps raw model trust at `70/100`. Production-style release gates should use signed `.credora` packages.

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

Keep private keys out of git. `.gitignore` excludes `*.pem`, `data/signing_keys/`, and `data/packages/`.

## Dashboard verification

```powershell
& ".venv\Scripts\python.exe" -m streamlit run dashboard\app.py --server.port 8501
```

Open `http://localhost:8501`, run the demo model, and confirm the report contains these evidence modules:

- leakage and holdout check;
- privacy and memorization risk;
- explainability method, native or SHAP;
- behavior analysis;
- adversarial validation;
- deployment gate;
- remediation plan.

## API verification

```powershell
& ".venv\Scripts\python.exe" -m uvicorn api.main:app --host 127.0.0.1 --port 8010
```

In a second terminal:

```cmd
curl http://127.0.0.1:8010/health
```

Expected response includes `"status":"ok"`.

## Git hygiene

Commit source files only. Do not commit regenerated local artifacts unless you intentionally want to update fixtures or reports.

Common generated paths:

- `.pytest_tmp/`
- `reports/trust_reports/*.json`
- `data/registry/*.sqlite3`
- `data/packages/`
- `data/signing_keys/`
