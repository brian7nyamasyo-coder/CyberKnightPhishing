
from datetime import datetime
from html import escape

from config import (
    REPORTS_DIR,
    MAX_REPORTS,
    HTML_REPORT_PREFIX,
    APP_NAME,
    APP_VERSION
)


def cleanup_old_reports(reports_dir):
    """Keep only the newest configured number of HTML reports."""

    reports = sorted(
        reports_dir.glob(f"{HTML_REPORT_PREFIX}*.html"),
        key=lambda report: report.stat().st_mtime,
        reverse=True
    )

    for old_report in reports[MAX_REPORTS:]:
        old_report.unlink()


def generate_html_report(
    email,
    url,
    sender_result,
    url_result,
    content_result,
    header_result,
    brand_result,
    overall_result
):
    """Generate a professional HTML phishing analysis report."""

    reports_dir = REPORTS_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().astimezone()

    filename = (
        f"{HTML_REPORT_PREFIX}"
        f"{timestamp.strftime('%Y%m%d_%H%M%S')}.html"
    )

    report_path = reports_dir / filename

    risk = overall_result["risk"]

    risk_colors = {
        "LOW": "#16a34a",
        "MEDIUM": "#d97706",
        "HIGH": "#dc2626"
    }

    risk_color = risk_colors.get(risk, "#64748b")

    def create_indicator_list(result):
        indicators = result.get("indicators", [])

        if not indicators:
            return "<li>No suspicious indicators detected.</li>"

        return "".join(
            f"<li>{escape(str(item))}</li>"
            for item in indicators
        )

    def create_section(title, result, score_label=None):
        score_html = ""

        if score_label:
            score_html = (
                f"<p><strong>{escape(score_label)}:</strong> "
                f"{escape(str(result.get('score', 0)))}</p>"
            )

        return f"""
        <section class="panel">
            <h2>{escape(title)}</h2>

            <p><strong>Risk:</strong>
            {escape(str(result.get('risk', 'UNKNOWN')))}</p>

            {score_html}

            <ul>
                {create_indicator_list(result)}
            </ul>
        </section>
        """

    # Security recommendations
    if risk == "HIGH":
        recommendations = [
            "Treat this message as high risk pending verification.",
            "Do not click suspicious links or provide sensitive information.",
            "Verify the sender through an independently obtained official contact channel."
        ]

    elif risk == "MEDIUM":
        recommendations = [
            "Investigate the detected indicators before trusting the message.",
            "Verify unexpected requests through an official contact channel."
        ]

    else:
        recommendations = [
            "No major indicators were detected by this heuristic scan.",
            "A low score does not guarantee that the message is safe."
        ]

    recommendation_html = "".join(
        f"<li>{escape(item)}</li>"
        for item in recommendations
    )

    # Component sections
    sections = ""

    sections += create_section(
        "Sender Analysis",
        sender_result
    )

    sections += create_section(
        "URL Analysis",
        url_result,
        "Score"
    )

    sections += create_section(
        "Brand Impersonation Analysis",
        brand_result,
        "Score"
    )

    sections += create_section(
        "Email Content Analysis",
        content_result,
        "Score"
    )

    sections += create_section(
        "Email Header Analysis",
        header_result,
        "Score"
    )

    # Overall component scores
    component_scores = overall_result.get(
        "component_scores", {}
    )

    component_score_html = "".join(
        f"""
        <li>
            <strong>{escape(name.title())}:</strong>
            {escape(str(score))}
        </li>
        """
        for name, score in component_scores.items()
    )

    # HTML document
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>{escape(APP_NAME)} Security Report - v{escape(APP_VERSION)}</title>

<style>
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 30px;
    background: #0f172a;
    color: #e2e8f0;
    font-family: Arial, sans-serif;
}}

.container {{
    max-width: 950px;
    margin: auto;
}}

header {{
    text-align: center;
    padding: 30px;
    background: #1e293b;
    border-radius: 12px;
}}

header h1 {{
    color: #38bdf8;
    margin-bottom: 8px;
}}

.version {{
    color: #94a3b8;
    font-size: 14px;
}}

.panel {{
    background: #1e293b;
    padding: 22px;
    margin-top: 20px;
    border-radius: 10px;
    border: 1px solid #334155;
}}

h2 {{
    color: #38bdf8;
}}

li {{
    margin-bottom: 10px;
    line-height: 1.5;
}}

.metadata {{
    overflow-wrap: anywhere;
}}

.risk {{
    color: {risk_color};
    font-size: 32px;
    font-weight: bold;
}}

.score {{
    font-size: 24px;
    font-weight: bold;
}}

footer {{
    text-align: center;
    margin-top: 30px;
    color: #94a3b8;
    font-size: 13px;
}}

@media print {{
    body {{
        background: white;
        color: black;
    }}

    .panel, header {{
        background: white;
        color: black;
        border: 1px solid #ccc;
        break-inside: avoid;
    }}

    h2, header h1 {{
        color: #0f172a;
    }}
}}
</style>
</head>

<body>

<div class="container">

<header>
    <h1>{escape(APP_NAME.upper())}</h1>
    <p class="version">Version {escape(APP_VERSION)}</p>
    <p>PHISHING DETECTION AND SECURITY ANALYSIS</p>
    <p>Automated Security Assessment Report</p>
</header>

<section class="panel">
    <h2>Overall Security Assessment</h2>

    <p class="risk">{escape(str(risk))} RISK</p>

    <p class="score">
        Score: {overall_result['score']}/100
    </p>

    <hr>

    <div class="metadata">
        <p><strong>Analysis date:</strong>
        {escape(timestamp.strftime('%Y-%m-%d %H:%M:%S %Z'))}</p>

        <p><strong>Sender:</strong>
        {escape(str(email))}</p>

        <p><strong>URL:</strong>
        {escape(str(url))}</p>
    </div>
</section>

<section class="panel">
    <h2>Component Score Breakdown</h2>
    <ul>
        {component_score_html}
    </ul>
</section>

{sections}

<section class="panel">
    <h2>Security Recommendations</h2>
    <ul>
        {recommendation_html}
    </ul>
</section>

<section class="panel">
    <h2>Important Notice</h2>

    <p>
    This report uses heuristic analysis. Its risk score is not
    a probability of phishing and cannot guarantee that a message
    is safe or malicious.
    </p>

    <p>
    Human review and independent verification are recommended.
    </p>
</section>

<footer>
    {escape(APP_NAME)} |
    Version {escape(APP_VERSION)} |
    Generated automatically
</footer>

</div>

</body>
</html>
"""

    report_path.write_text(
        html_content,
        encoding="utf-8"
    )

    cleanup_old_reports(reports_dir)

    return report_path
