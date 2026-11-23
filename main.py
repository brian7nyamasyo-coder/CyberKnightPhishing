
from analyzers.sender_analyzer import analyze_sender
from analyzers.url_analyzer import analyze_url
from analyzers.content_analyzer import analyze_content
from analyzers.header_analyzer import analyze_headers
from analyzers.brand_analyzer import analyze_brand

from core.detector import calculate_overall_risk
from core.input_handler import get_required_input, get_multiline_input
from core.logger import logger

from reports.report_generator import generate_report
from reports.html_report_generator import generate_html_report

from config import APP_NAME, APP_VERSION


def main():

    logger.info(
        "%s v%s analysis started.",
        APP_NAME,
        APP_VERSION
    )

    print("=" * 45)
    print(f"   {APP_NAME.upper()}")
    print(f"   Version: {APP_VERSION}")
    print("=" * 45)

    # 1. Sender analysis
    email = get_required_input(
        "\nEnter sender email address: "
    )

    sender_result = analyze_sender(email)

    print("\n========== SENDER ANALYSIS ==========")
    print("Email:", email)
    print("Valid format:", sender_result["valid"])
    print("Risk level:", sender_result["risk"])

    for indicator in sender_result["indicators"]:
        print("-", indicator)

    # 2. URL analysis
    url = get_required_input(
        "\nEnter URL to analyze: "
    )

    url_result = analyze_url(url)
    brand_result = analyze_brand(url)

    print("\n========== URL ANALYSIS =============")
    print("URL:", url)
    print("Valid structure:", url_result["valid"])
    print("Risk level:", url_result["risk"])
    print("Risk score:", url_result["score"], "/100")

    for indicator in url_result["indicators"]:
        print("-", indicator)

    if not url_result["indicators"]:
        print("No suspicious indicators detected.")

    # 3. Brand impersonation analysis
    print("\n========== BRAND ANALYSIS ===========")
    print("Risk level:", brand_result["risk"])
    print("Risk score:", brand_result["score"])

    for indicator in brand_result["indicators"]:
        print("-", indicator)

    if not brand_result["indicators"]:
        print("No brand impersonation indicators detected.")

    # 4. Content analysis
    content = get_multiline_input(
        "Paste email content below."
    )

    content_result = analyze_content(content)

    print("\n========== CONTENT ANALYSIS =========")
    print("Risk level:", content_result["risk"])
    print("Risk score:", content_result["score"])

    for indicator in content_result["indicators"]:
        print("-", indicator)

    if not content_result["indicators"]:
        print("No suspicious indicators detected.")

    # 5. Email header analysis
    raw_headers = get_multiline_input(
        "Paste raw email headers below."
    )

    header_result = analyze_headers(raw_headers)

    print("\n========== HEADER ANALYSIS ==========")
    print("Valid:", header_result["valid"])
    print("Risk level:", header_result["risk"])
    print("Risk score:", header_result["score"])

    for indicator in header_result["indicators"]:
        print("-", indicator)

    # 6. Overall assessment
    overall_result = calculate_overall_risk(
        sender_result,
        url_result,
        content_result,
        header_result,
        brand_result
    )

    logger.info(
        "Analysis completed. Overall risk: %s | Score: %s/100",
        overall_result["risk"],
        overall_result["score"]
    )

    print("\n========== OVERALL ASSESSMENT ========")
    print("Overall risk:", overall_result["risk"])
    print("Combined risk score:", overall_result["score"], "/100")

    print("\nComponent scores:")
    print("Sender:", overall_result["component_scores"]["sender"], "/15")
    print("URL:", overall_result["component_scores"]["url"], "/20")
    print("Content:", overall_result["component_scores"]["content"], "/25")
    print("Headers:", overall_result["component_scores"]["headers"], "/25")
    print("Brand:", overall_result["component_scores"]["brand"], "/15")

    print("\nCombined indicators:")

    if overall_result["indicators"]:
        for indicator in overall_result["indicators"]:
            print("-", indicator)
    else:
        print("No suspicious indicators detected.")

    print("\n====================================")
    print("       ANALYSIS COMPLETE")
    print("====================================")

    # 7. Generate TXT report
    try:
        report_path = generate_report(
            email,
            url,
            sender_result,
            url_result,
            content_result,
            header_result,
            brand_result,
            overall_result
        )

        logger.info("TXT report generated successfully.")

        print("\n========== REPORT GENERATED ==========")
        print("Report saved to:", report_path)

    except OSError:
        logger.exception("TXT report generation failed.")
        print("\nTXT report could not be saved.")

    # 8. Generate HTML report
    try:
        html_report_path = generate_html_report(
            email,
            url,
            sender_result,
            url_result,
            content_result,
            header_result,
            brand_result,
            overall_result
        )

        logger.info("HTML report generated successfully.")

        print("\n========== HTML REPORT GENERATED ==========")
        print("HTML report saved to:", html_report_path)

    except OSError:
        logger.exception("HTML report generation failed.")
        print("\nHTML report could not be saved.")


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        logger.warning("Analysis cancelled by user.")
        print("\n\nAnalysis cancelled by user.")

    except EOFError:
        logger.warning("Input ended unexpectedly.")
        print("\n\nInput ended unexpectedly. Analysis cancelled.")

    except Exception:
        logger.exception("Unexpected application error.")
        print("\nAn unexpected error occurred. Check logs/cyberknight.log.")
