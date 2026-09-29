from __future__ import annotations

import argparse

from auditor.checks import run_all_checks
from auditor.report import build_report, print_report, save_json_report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit a Linux system for common security configuration issues."
    )

    parser.add_argument(
        "--json",
        default="security-report.json",
        help="Path for the JSON report.",
    )

    args = parser.parse_args()

    results = run_all_checks()
    report = build_report(results)

    print_report(report)

    output = save_json_report(
        report,
        args.json,
    )

    print()
    print(f"JSON report saved to: {output}")


if __name__ == "__main__":
    main()
