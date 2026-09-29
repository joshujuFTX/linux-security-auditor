from pathlib import Path

from auditor.html_report import render_html, save_html_report


def sample_report():
    return {
        "tool": "Linux Security Auditor",
        "version": "1.0.0",
        "generated_at": "2026-09-29T00:00:00+00:00",
        "summary": {
            "critical": 0,
            "high": 1,
            "medium": 1,
            "low": 0,
            "info": 2,
        },
        "findings": [
            {
                "check": "ssh_configuration",
                "status": "WARN",
                "severity": "high",
                "message": "SSH root login is configured as 'yes'.",
            },
            {
                "check": "firewall",
                "status": "INFO",
                "severity": "medium",
                "message": "No supported firewall manager detected.",
            },
        ],
    }


def test_render_html():
    html = render_html(sample_report())

    assert "Linux Security Audit" in html
    assert "SSH root login" in html
    assert "Security Findings" in html
    assert 'data-filter="high"' in html


def test_save_html_report(tmp_path):
    path = tmp_path / "nested" / "report.html"

    output = save_html_report(
        sample_report(),
        str(path),
    )

    assert output == path
    assert path.exists()

    content = path.read_text(
        encoding="utf-8",
    )

    assert "<!DOCTYPE html>" in content
    assert "Security Findings" in content
