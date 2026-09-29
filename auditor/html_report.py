from __future__ import annotations

import html
from pathlib import Path
from typing import Any


SEVERITY_META = {
    "critical": ("Critical", "#ff5f5f", "#2a1418"),
    "high": ("High", "#ff8b6b", "#281914"),
    "medium": ("Medium", "#f2c866", "#292312"),
    "low": ("Low", "#7fc8ff", "#13202b"),
    "info": ("Info", "#9ca8b8", "#181e27"),
}


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def finding_details(finding: dict[str, Any]) -> str:
    extra = []

    if "port" in finding:
        extra.append(
            f'<span class="detail-pill">Port {esc(finding["port"])}</span>'
        )

    if "count" in finding:
        extra.append(
            f'<span class="detail-pill">{esc(finding["count"])} services</span>'
        )

    if finding.get("services"):
        extra.append(
            f'<span class="detail-pill">{len(finding["services"])} service names</span>'
        )

    return "".join(extra)


def render_html(report: dict[str, Any]) -> str:
    summary = report["summary"]
    findings = report["findings"]

    severity_cards = ""

    for severity in ["critical", "high", "medium", "low", "info"]:
        label, accent, background = SEVERITY_META[severity]

        severity_cards += f"""
        <div class="summary-card">
          <div class="summary-accent" style="background:{accent};"></div>
          <div class="summary-label">{label}</div>
          <div class="summary-value">{summary[severity]}</div>
        </div>
        """

    finding_cards = ""

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        label, accent, background = SEVERITY_META.get(
            severity,
            SEVERITY_META["info"],
        )

        status = finding.get("status", "INFO")
        check = finding.get("check", "unknown").replace("_", " ")
        message = finding.get("message", "")

        finding_cards += f"""
        <article
          class="finding-card"
          data-severity="{esc(severity)}"
        >
          <div class="finding-top">
            <div class="finding-title-row">
              <span
                class="severity-dot"
                style="background:{accent}; box-shadow:0 0 12px {accent}66;"
              ></span>

              <span class="finding-check">
                {esc(check)}
              </span>
            </div>

            <span
              class="severity-badge"
              style="color:{accent}; background:{background}; border-color:{accent}33;"
            >
              {esc(label)}
            </span>
          </div>

          <div class="finding-message">
            {esc(message)}
          </div>

          <div class="finding-bottom">
            <span class="status status-{esc(status.lower())}">
              {esc(status)}
            </span>

            <div class="details">
              {finding_details(finding)}
            </div>
          </div>
        </article>
        """

    if not finding_cards:
        finding_cards = """
        <div class="empty-state">
          <div class="empty-icon">✓</div>
          <div class="empty-title">No findings returned</div>
          <div class="empty-text">
            The audit completed without producing findings.
          </div>
        </div>
        """

    generated = esc(report.get("generated_at", "Unknown"))
    version = esc(report.get("version", "Unknown"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>Linux Security Audit</title>

  <style>
    :root {{
      --bg: #080a0e;
      --panel: #0f1217;
      --panel-2: #12161d;
      --border: #1d232d;
      --border-soft: #171c24;
      --text: #f3f6fa;
      --muted: #8b95a5;
      --muted-2: #626d7c;
      --green: #6ee7a8;
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(
          circle at 90% 0%,
          rgba(125, 145, 255, 0.08),
          transparent 28%
        ),
        radial-gradient(
          circle at 10% 0%,
          rgba(110, 231, 168, 0.04),
          transparent 22%
        ),
        var(--bg);
      color: var(--text);
      font-family:
        Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    }}

    .shell {{
      width: min(1180px, calc(100% - 34px));
      margin: 0 auto;
      padding: 34px 0 60px;
    }}

    .header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 20px;
      margin-bottom: 24px;
    }}

    .eyebrow {{
      color: #7f8998;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.16em;
      text-transform: uppercase;
    }}

    h1 {{
      margin: 8px 0 8px;
      font-size: clamp(30px, 5vw, 46px);
      line-height: 0.98;
      letter-spacing: -0.045em;
    }}

    .subtitle {{
      color: var(--muted);
      font-size: 13px;
      max-width: 650px;
      line-height: 1.6;
    }}

    .header-meta {{
      padding: 12px 14px;
      border: 1px solid var(--border);
      background: rgba(15, 18, 23, 0.78);
      border-radius: 12px;
      min-width: 180px;
    }}

    .meta-label {{
      color: var(--muted-2);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      font-weight: 800;
    }}

    .meta-value {{
      margin-top: 6px;
      font-size: 11px;
      color: #cfd7e1;
      word-break: break-word;
    }}

    .panel {{
      border: 1px solid var(--border);
      background: linear-gradient(
        180deg,
        rgba(17, 21, 28, 0.97),
        rgba(13, 16, 22, 0.97)
      );
      border-radius: 15px;
      box-shadow: 0 18px 50px rgba(0, 0, 0, 0.25);
    }}

    .summary-panel {{
      padding: 15px;
    }}

    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 9px;
    }}

    .summary-card {{
      position: relative;
      overflow: hidden;
      min-height: 96px;
      padding: 15px;
      background: #0c0f14;
      border: 1px solid var(--border-soft);
      border-radius: 11px;
    }}

    .summary-accent {{
      position: absolute;
      inset: 0 auto 0 0;
      width: 2px;
    }}

    .summary-label {{
      color: var(--muted);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 800;
    }}

    .summary-value {{
      margin-top: 11px;
      font-size: 28px;
      font-weight: 750;
      letter-spacing: -0.04em;
    }}

    .section {{
      margin-top: 14px;
      padding: 18px;
    }}

    .section-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 15px;
    }}

    .section-title {{
      margin: 0;
      font-size: 14px;
      font-weight: 750;
    }}

    .section-description {{
      color: var(--muted-2);
      font-size: 11px;
      margin-top: 3px;
    }}

    .filters {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }}

    .filter {{
      border: 1px solid var(--border);
      background: #0b0e13;
      color: var(--muted);
      border-radius: 999px;
      padding: 7px 10px;
      cursor: pointer;
      font-size: 10px;
      font-weight: 750;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}

    .filter:hover,
    .filter.active {{
      color: var(--text);
      border-color: #343d4a;
      background: #141922;
    }}

    .findings {{
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}

    .finding-card {{
      border: 1px solid var(--border-soft);
      background: rgba(9, 12, 17, 0.82);
      border-radius: 11px;
      padding: 14px;
      transition:
        border-color 0.18s ease,
        transform 0.18s ease,
        background 0.18s ease;
    }}

    .finding-card:hover {{
      border-color: #2c3440;
      background: #0d1117;
      transform: translateY(-1px);
    }}

    .finding-top {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }}

    .finding-title-row {{
      display: flex;
      align-items: center;
      gap: 9px;
      min-width: 0;
    }}

    .severity-dot {{
      width: 7px;
      height: 7px;
      border-radius: 50%;
      flex: 0 0 auto;
    }}

    .finding-check {{
      color: #dbe2eb;
      font-size: 12px;
      font-weight: 700;
      text-transform: capitalize;
    }}

    .severity-badge {{
      border: 1px solid;
      border-radius: 999px;
      padding: 5px 8px;
      font-size: 9px;
      font-weight: 850;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      white-space: nowrap;
    }}

    .finding-message {{
      color: #9da8b7;
      font-size: 11px;
      line-height: 1.55;
      margin: 9px 0 11px 16px;
    }}

    .finding-bottom {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-left: 16px;
    }}

    .status {{
      font-size: 9px;
      font-weight: 850;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }}

    .status-pass {{
      color: var(--green);
    }}

    .status-warn {{
      color: #f0c96a;
    }}

    .status-info {{
      color: #8190a2;
    }}

    .details {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }}

    .detail-pill {{
      padding: 4px 7px;
      border-radius: 6px;
      color: var(--muted-2);
      background: #121720;
      border: 1px solid var(--border-soft);
      font-size: 9px;
    }}

    .empty-state {{
      text-align: center;
      padding: 45px 20px;
      border: 1px dashed #242b35;
      border-radius: 11px;
      background: #0b0e13;
    }}

    .empty-icon {{
      margin: 0 auto 12px;
      width: 34px;
      height: 34px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background: rgba(110, 231, 168, 0.08);
      color: var(--green);
      border: 1px solid rgba(110, 231, 168, 0.14);
    }}

    .empty-title {{
      font-size: 13px;
      font-weight: 750;
    }}

    .empty-text {{
      margin-top: 5px;
      color: var(--muted-2);
      font-size: 11px;
    }}

    .footer {{
      margin-top: 14px;
      display: flex;
      justify-content: space-between;
      gap: 14px;
      color: var(--muted-2);
      font-size: 10px;
    }}

    @media (max-width: 850px) {{
      .summary-grid {{
        grid-template-columns: repeat(3, 1fr);
      }}

      .header {{
        flex-direction: column;
      }}

      .header-meta {{
        width: 100%;
      }}
    }}

    @media (max-width: 600px) {{
      .shell {{
        width: min(100% - 22px, 1180px);
        padding-top: 20px;
      }}

      .summary-grid {{
        grid-template-columns: repeat(2, 1fr);
      }}

      .section-header {{
        align-items: flex-start;
        flex-direction: column;
      }}

      .finding-bottom {{
        align-items: flex-start;
        flex-direction: column;
      }}

      .details {{
        justify-content: flex-start;
      }}

      .footer {{
        flex-direction: column;
      }}
    }}
  </style>
</head>

<body>
  <main class="shell">

    <header class="header">
      <div>
        <div class="eyebrow">Host Security Assessment</div>

        <h1>Linux Security Audit</h1>

        <div class="subtitle">
          Automated inspection of Linux accounts, network exposure,
          services, SSH configuration, sensitive file permissions,
          and firewall state.
        </div>
      </div>

      <div class="header-meta">
        <div class="meta-label">Audit Metadata</div>
        <div class="meta-value">Generated {generated}</div>
        <div class="meta-value">Auditor v{version}</div>
      </div>
    </header>

    <section class="panel summary-panel">
      <div class="summary-grid">
        {severity_cards}
      </div>
    </section>

    <section class="panel section">
      <div class="section-header">
        <div>
          <h2 class="section-title">Security Findings</h2>
          <div class="section-description">
            Review observations by severity and check category.
          </div>
        </div>

        <div class="filters">
          <button class="filter active" data-filter="all">
            All
          </button>

          <button class="filter" data-filter="critical">
            Critical
          </button>

          <button class="filter" data-filter="high">
            High
          </button>

          <button class="filter" data-filter="medium">
            Medium
          </button>

          <button class="filter" data-filter="low">
            Low
          </button>

          <button class="filter" data-filter="info">
            Info
          </button>
        </div>
      </div>

      <div class="findings" id="findings">
        {finding_cards}
      </div>
    </section>

    <footer class="footer">
      <div>
        Linux Security Auditor · Local host assessment
      </div>

      <div>
        Generated from the auditor's structured report
      </div>
    </footer>

  </main>

  <script>
    const filters = document.querySelectorAll(".filter");
    const cards = document.querySelectorAll(".finding-card");

    filters.forEach((filter) => {{
      filter.addEventListener("click", () => {{
        const value = filter.dataset.filter;

        filters.forEach((item) => {{
          item.classList.remove("active");
        }});

        filter.classList.add("active");

        cards.forEach((card) => {{
          const severity = card.dataset.severity;

          if (value === "all" || severity === value) {{
            card.style.display = "";
          }} else {{
            card.style.display = "none";
          }}
        }});
      }});
    }});
  </script>
</body>
</html>
"""


def save_html_report(
    report: dict[str, Any],
    path: str = "reports/security-report.html",
) -> Path:
    output = Path(path)

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        render_html(report),
        encoding="utf-8",
    )

    return output
