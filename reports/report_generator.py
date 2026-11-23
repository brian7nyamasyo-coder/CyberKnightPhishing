
from datetime import datetime

from config import (
    REPORTS_DIR,
    MAX_REPORTS,
    REPORT_PREFIX,
    APP_NAME,
    APP_VERSION
)


def cleanup_old_reports(reports_dir):
    """Keep only the newest configured number of TXT reports."""

    reports = sorted(
        reports_dir.glob(f"{REPORT_PREFIX}*.txt"),
        key=lambda report: report.stat().st_mtime,
        reverse=True
    )

    for old_report in reports[MAX_REPORTS:]:
        old_report.unlink()


def generate_report(
    email,
    url,
    sender_result,
    url_result,
    content_result,
    header_result,
    brand_result,
    overall_result
):
    """Generate and save a CyberKnight phishing analysis report."""

    reports_dir = REPORTS_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().astimezone()

    filename = (
        f"{REPORT_PREFIX}"
        f"{timestamp.strftime('%Y%m%d_%H%M%S')}.txt"
    )

    report_path = reports_dir / filename

    report = []

    report.append("=" * 55)
    report.append(f"          {APP_NAME.upper()}")
    report.append(f"               Version: {APP_VERSION}")
    report.append("               ANALYSIS REPORT")
    report.append("=" * 55)

    report.append(f"\nDate: {timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    report.append(f"Sender email: {email}")
    report.append(f"URL analyzed: {url}")

    report.append("\n" + "=" * 55)
    report.append("SENDER ANALYSIS")
    report.append("=" * 55)
    report.append(f"Risk: {sender_result['risk']}")
    report.append(f"Valid format: {sender_result['valid']}")

    for indicator in sender_result["indicators"]:
        report.append(f"- {indicator}")

    report.append("\n" + "=" * 55)
    report.append("URL ANALYSIS")
    report.append("=" * 55)
    report.append(f"Risk: {url_result['risk']}")
    report.append(f"Score: {url_result['score']}/100")
    report.append(f"Valid structure: {url_result['valid']}")

    for indicator in url_result["indicators"]:
        report.append(f"- {indicator}")

    report.append("\n" + "=" * 55)
    report.append("BRAND IMPERSONATION ANALYSIS")
    report.append("=" * 55)
    report.append(f"Risk: {brand_result['risk']}")
    report.append(f"Score: {brand_result['score']}")

    for indicator in brand_result["indicators"]:
        report.append(f"- {indicator}")

    if not brand_result["indicators"]:
        report.append("No brand impersonation indicators detected.")

    report.append("\n" + "=" * 55)
    report.append("CONTENT ANALYSIS")
    report.append("=" * 55)
    report.append(f"Risk: {content_result['risk']}")
    report.append(f"Score: {content_result['score']}")

    for indicator in content_result["indicators"]:
        report.append(f"- {indicator}")

    report.append("\n" + "=" * 55)
    report.append("EMAIL HEADER ANALYSIS")
    report.append("=" * 55)
    report.append(f"Risk: {header_result['risk']}")
    report.append(f"Score: {header_result['score']}")
    report.append(f"Valid: {header_result['valid']}")

    for indicator in header_result["indicators"]:
        report.append(f"- {indicator}")

    report.append("\n" + "=" * 55)
    report.append("OVERALL SECURITY ASSESSMENT")
    report.append("=" * 55)
    report.append(f"Overall risk: {overall_result['risk']}")
    report.append(f"Combined score: {overall_result['score']}/100")

    report.append("\nComponent scores:")

    for component, score in overall_result["component_scores"].items():
        report.append(f"- {component.title()}: {score}")

    report.append("\nDetected indicators:")

    for indicator in overall_result["indicators"]:
        report.append(f"- {indicator}")

    if not overall_result["indicators"]:
        report.append("No suspicious indicators detected.")

    report.append("\n" + "=" * 55)
    report.append("SECURITY RECOMMENDATIONS")
    report.append("=" * 55)

    if overall_result["risk"] == "HIGH":
        report.append("- Treat this message as high risk pending verification.")
        report.append("- Do not click its links or provide sensitive information.")
        report.append("- Verify the sender through an independently obtained official contact channel.")

    elif overall_result["risk"] == "MEDIUM":
        report.append("- Investigate the suspicious indicators before trusting the message.")
        report.append("- Verify unexpected requests through an official channel.")

    else:
        report.append("- No major indicators were detected by this heuristic scan.")
        report.append("- A low score does not guarantee that the message is safe.")

    report.append("\n")
    report.append("NOTE: This report is based on heuristic analysis.")
    report.append("The risk score is not a probability of phishing.")
    report.append("Human review and independent verification are advised.")
    report.append("\n" + "=" * 55)
    report.append("             END OF REPORT")
    report.append("=" * 55)

    report_path.write_text(
        "\n".join(report),
        encoding="utf-8"
    )

    cleanup_old_reports(reports_dir)

    return report_path
