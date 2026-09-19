from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYTHON = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe" if sys.platform.startswith("win") else PROJECT_ROOT / ".venv" / "bin" / "python"
if not PYTHON.exists():
    PYTHON = Path(sys.executable)


def run_step(name: str, command: list[str], timeout: int | None = None) -> None:
    print(f"\n== {name} ==")
    print(" ".join(command))
    completed = subprocess.run(command, cwd=PROJECT_ROOT, text=True, timeout=timeout)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def wait_http(url: str, timeout_seconds: int = 20) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if 200 <= response.status < 500:
                    print(json.dumps({"url": url, "status": response.status}, indent=2))
                    return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(1)
    raise RuntimeError(f"{url} did not respond within {timeout_seconds}s: {last_error}")


def smoke_server(name: str, command: list[str], url: str) -> None:
    print(f"\n== {name} ==")
    process = subprocess.Popen(command, cwd=PROJECT_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        wait_http(url)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Credora's local Phase 3 verification suite.")
    parser.add_argument("--skip-scan", action="store_true", help="Skip the full sample assessment scan.")
    parser.add_argument("--skip-release-gate", action="store_true", help="Skip signed package creation and release gate validation.")
    parser.add_argument("--with-api", action="store_true", help="Start the API and verify /health responds.")
    parser.add_argument("--with-dashboard", action="store_true", help="Start Streamlit and verify the dashboard responds.")
    args = parser.parse_args()

    run_step("Compile Python files", [str(PYTHON), "-m", "compileall", "core", "modules", "scripts", "api", "tests"])
    run_step("Run tests", [str(PYTHON), "-m", "pytest", "-q", "--basetemp", ".pytest_tmp"])

    if not args.skip_scan:
        run_step("Run sample Credora assessment", [str(PYTHON), "scripts/run_phase1_scan.py", "--no-docx"], timeout=180)

    if not args.skip_release_gate:
        with tempfile.TemporaryDirectory(prefix="credora-verify-") as temp_dir:
            temp = Path(temp_dir)
            private_key = temp / "ci-private.pem"
            public_key = temp / "ci-public.pem"
            package = temp / "traffic_rf_v1.credora"
            run_step("Generate temporary signing key", [str(PYTHON), "scripts/package_model.py", "keygen", "--private-key", str(private_key), "--public-key", str(public_key)])
            run_step(
                "Create signed sample package",
                [
                    str(PYTHON),
                    "scripts/package_model.py",
                    "create",
                    "--model",
                    "data/sample_models/traffic_rf_v1.joblib",
                    "--metadata",
                    "data/metadata/traffic_rf_v1_metadata.json",
                    "--requirements",
                    "data/sample_requirements/requirements_demo.txt",
                    "--private-key",
                    str(private_key),
                    "--output",
                    str(package),
                ],
            )
            run_step("Run signed release gate", [str(PYTHON), "scripts/phase3_release_gate.py", "--package", str(package), "--trust-key", str(public_key), "--minimum-score", "85"], timeout=180)

    if args.with_api:
        smoke_server("API smoke check", [str(PYTHON), "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8010"], "http://127.0.0.1:8010/health")

    if args.with_dashboard:
        smoke_server("Dashboard smoke check", [str(PYTHON), "-m", "streamlit", "run", "dashboard/app.py", "--server.headless", "true", "--server.address", "127.0.0.1", "--server.port", "8501"], "http://127.0.0.1:8501")

    print("\nCredora verification completed successfully.")


if __name__ == "__main__":
    main()
