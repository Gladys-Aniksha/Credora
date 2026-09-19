# Credora Phase 4 Runbook - Signed Final Trust Reports

Phase 4 makes the final JSON trust report tamper-evident. The model package can already be signed before scanning; this phase signs the assessment result after Credora finishes the scan.

## What Phase 4 Adds

- Ed25519 signatures for final trust report JSON files.
- Independent report verification from CMD without opening the dashboard.
- Tamper detection: changing the score, findings, recommendations, or any other signed report field invalidates the signature.
- Admin-managed trusted public signers in the dashboard and API.
- Dashboard report status showing whether a report is unsigned, signed by an unknown key, or verified by a trusted signer.

## Generate a Report Signing Keypair

Run from `C:\Users\glady\Mini project`:

```cmd
.venv\Scripts\python.exe scripts\generate_report_signing_keys.py --private-key data\signing_keys\report_private.pem --public-key data\signing_keys\report_public.pem
```

Keep `report_private.pem` private. Add the contents of `report_public.pem` in the dashboard under Admin -> Policy -> Trusted Ed25519 public signers.

## Sign an Existing Trust Report

```cmd
.venv\Scripts\python.exe scripts\sign_trust_report.py --report reports\trust_reports\1\traffic_rf_v1_phase3_trust_report.json --private-key data\signing_keys\report_private.pem --signer "Credora Release"
```

You can also write to a new file:

```cmd
.venv\Scripts\python.exe scripts\sign_trust_report.py --report reports\trust_reports\1\traffic_rf_v1_phase3_trust_report.json --private-key data\signing_keys\report_private.pem --signer "Credora Release" --output reports\trust_reports\1\traffic_rf_v1_phase4_signed_report.json
```

## Verify a Signed Report

```cmd
.venv\Scripts\python.exe scripts\verify_trust_report.py --report reports\trust_reports\1\traffic_rf_v1_phase3_trust_report.json --public-key data\signing_keys\report_public.pem
```

A valid report prints `"verified": true`. If the report was edited after signing, the command exits with code `2` and explains why verification failed.

## Sign During a Scan

```cmd
.venv\Scripts\python.exe scripts\run_phase1_scan.py --report-signing-private-key data\signing_keys\report_private.pem --report-signer "Credora Release"
```

That produces the normal report plus a `report_signature` block.

## Security Rule

Credora stores trusted public keys only. Do not paste private keys into the dashboard, metadata, README, or GitHub. The private key belongs outside source control and should be rotated if it is ever shared accidentally.
