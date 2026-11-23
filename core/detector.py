
def calculate_overall_risk(
    sender_result,
    url_result,
    content_result,
    header_result,
    brand_result
):
    """
    Calculate a combined phishing-risk score out of 100.

    This is a heuristic assessment, not a probability.
    """

    # 1. Sender score: maximum 15 points
    sender_points = {
        "LOW": 0,
        "MEDIUM": 8,
        "HIGH": 15
    }

    sender_score = sender_points.get(
        sender_result.get("risk", "HIGH"), 15
    )

    # 2. URL score: maximum 20 points
    url_score = min(
        url_result.get("score", 0),
        20
    )

    # 3. Content score: maximum 25 points
    content_score = min(
        content_result.get("score", 0) * 3,
        25
    )

    # 4. Header score: maximum 25 points
    header_score = min(
        header_result.get("score", 0) * 3,
        25
    )

    # 5. Brand score: maximum 15 points
    brand_score = min(
        brand_result.get("score", 0) * 3,
        15
    )

    # Calculate total
    total_score = (
        sender_score
        + url_score
        + content_score
        + header_score
        + brand_score
    )

    # Determine overall risk
    if total_score >= 60:
        overall_risk = "HIGH"

    elif total_score >= 30:
        overall_risk = "MEDIUM"

    else:
        overall_risk = "LOW"

    # Combine indicators
    components = [
        ("Sender", sender_result),
        ("URL", url_result),
        ("Content", content_result),
        ("Headers", header_result),
        ("Brand", brand_result)
    ]

    indicators = []

    for component_name, result in components:
        for indicator in result.get("indicators", []):
            indicators.append(
                f"{component_name}: {indicator}"
            )

    return {
        "risk": overall_risk,
        "score": total_score,
        "indicators": indicators,
        "component_scores": {
            "sender": sender_score,
            "url": url_score,
            "content": content_score,
            "headers": header_score,
            "brand": brand_score
        }
    }
