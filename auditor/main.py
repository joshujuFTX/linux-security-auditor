from __future__ import annotations

import argparse

from auditor.checks import run_all_checks
from auditor.html_report import save_html_report
from auditor.report import (
    build_report,
    print_report,
    save_json_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Audit a Linux system for common "
            "security configuration issues."
        )
    )

    parser.add_argument(
        "--json",
        default="reports/security-report.json",
        help="Path for the JSON report.",
    )

    parser.add_argument(
        "--html",
        default="reports/security-report.html",
        help="Path for the HTML report.",
    )

    args = parser.parse_args()

    results = run_all_checks()

    report = build_report(results)

    print_report(report)

    json_output = save_json_report(
        report,
        args.json,
    )

    html_output = save_html_report(
        report,
        args.html,
    )

    print()
    print(f"JSON report saved to: {json_output}")
    print(f"HTML report saved to: {html_output}")


if __name__ == "__main__":
    main()
