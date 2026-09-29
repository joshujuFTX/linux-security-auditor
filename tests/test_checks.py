from pathlib import Path

from auditor.checks import (
    check_sensitive_permissions,
    parse_ssh_value,
)
from auditor.report import build_report, summarize


def test_parse_ssh_value():
    lines = [
        "# PermitRootLogin yes",
        "PermitRootLogin no",
        "PasswordAuthentication yes",
    ]

    assert parse_ssh_value(
        lines,
        "PermitRootLogin",
    ) == "no"

    assert parse_ssh_value(
        lines,
        "PasswordAuthentication",
    ) == "yes"


def test_summary():
    findings = [
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "medium"},
        {"severity": "info"},
    ]

    result = summarize(findings)

    assert result["high"] == 1
    assert result["medium"] == 2
    assert result["info"] == 1
    assert result["critical"] == 0


def test_build_report():
    results = [
        {
            "check": "example",
            "findings": [
                {
                    "status": "WARN",
                    "severity": "high",
                    "message": "Example finding",
                }
            ],
        }
    ]

    report = build_report(results)

    assert report["tool"] == "Linux Security Auditor"
    assert report["summary"]["high"] == 1
    assert report["findings"][0]["check"] == "example"


def test_sensitive_permission_check_returns_result():
    result = check_sensitive_permissions()

    assert result["check"] == "sensitive_file_permissions"
    assert "findings" in result
    assert isinstance(result["findings"], list)
