from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse

from auditor.checks import run_all_checks
from auditor.html_report import save_html_report
from auditor.report import build_report, save_json_report


BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_PATH = BASE_DIR / "web_dashboard.html"

app = FastAPI(
    title="Linux Security Auditor",
    description="Web interface for the Linux Security Auditor.",
    version="1.0.0",
)


def run_current_audit():
    results = run_all_checks()
    report = build_report(results)

    save_json_report(
        report,
        "reports/security-report.json",
    )

    save_html_report(
        report,
        "reports/security-report.html",
    )

    return report


@app.get("/")
def dashboard():
    if not TEMPLATE_PATH.exists():
        return JSONResponse(
            status_code=500,
            content={
                "error": "Dashboard template is missing.",
                "path": str(TEMPLATE_PATH),
            },
        )

    return FileResponse(
        TEMPLATE_PATH,
        media_type="text/html",
    )


@app.get("/api/audit")
def audit():
    return JSONResponse(run_current_audit())


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "Linux Security Auditor",
    }


@app.get("/reports/html")
def html_report():
    run_current_audit()

    path = Path(
        "reports/security-report.html"
    )

    return FileResponse(
        path,
        media_type="text/html",
    )


@app.get("/reports/json")
def json_report():
    run_current_audit()

    path = Path(
        "reports/security-report.json"
    )

    return FileResponse(
        path,
        media_type="application/json",
    )
