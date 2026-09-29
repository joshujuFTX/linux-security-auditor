from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def flatten_findings(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []

    for result in results:
        for finding in result.get("findings", []):
            findings.append({
                "check": result["check"],
                **finding,
            })

    return findings


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter()

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        counts[severity] += 1

    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
    }


def build_report(results: list[dict[str, Any]]) -> dict[str, Any]:
    findings = flatten_findings(results)

    findings.sort(
        key=lambda item: SEVERITY_ORDER.get(
            item.get("severity", "info"),
            99,
        )
    )

    return {
        "tool": "Linux Security Auditor",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summarize(findings),
        "findings": findings,
    }


def save_json_report(
    report: dict[str, Any],
    path: str = "security-report.json",
) -> Path:
    output = Path(path)

    output.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )

    return output


def print_report(report: dict[str, Any]) -> None:
    print()
    print("LINUX SECURITY AUDITOR")
    print("────────────────────────────────────────")

    summary = report["summary"]

    print()
    print("SUMMARY")
    print(f"  Critical : {summary['critical']}")
    print(f"  High     : {summary['high']}")
    print(f"  Medium   : {summary['medium']}")
    print(f"  Low      : {summary['low']}")
    print(f"  Info     : {summary['info']}")

    print()
    print("FINDINGS")

    for finding in report["findings"]:
        status = finding.get("status", "INFO")
        severity = finding.get("severity", "info").upper()
        message = finding.get("message", "")

        print(
            f"  [{status:<4}] "
            f"{severity:<8} "
            f"{finding['check']}: "
            f"{message}"
        )

    print()
    print(f"Generated: {report['generated_at']}")
