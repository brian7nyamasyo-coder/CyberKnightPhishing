
from email import policy
from email.parser import Parser


def analyze_headers(raw_headers):
    """
    Analyze email headers for defensive security investigation.
    Uses supplied header text only. Does not connect to email servers.
    """

    indicators = []
    score = 0

    try:
        message = Parser(policy=policy.default).parsestr(raw_headers)

    except Exception:
        return {
            "valid": False,
            "risk": "HIGH",
            "score": 100,
            "indicators": ["Unable to parse email headers"]
        }

    # 1. Extract important headers
    sender = message.get("From")
    reply_to = message.get("Reply-To")
    return_path = message.get("Return-Path")
    authentication = message.get_all("Authentication-Results", [])

    # 2. Check whether important headers are missing
    if not sender:
        indicators.append("Missing From header")
        score += 2

    if not return_path:
        indicators.append("Missing Return-Path header")
        score += 1

    # 3. Compare sender and reply destination
    if sender and reply_to:
        if sender.addresses and reply_to.addresses:

            sender_domain = sender.addresses[0].domain.lower()
            reply_domain = reply_to.addresses[0].domain.lower()

            if sender_domain != reply_domain:
                indicators.append(
                    "Reply-To domain differs from sender domain"
                )
                score += 3

    # 4. Examine authentication results
    if authentication:
        auth_text = " ".join(str(value) for value in authentication).lower()

        for method in ["spf", "dkim", "dmarc"]:
            if f"{method}=fail" in auth_text:
                indicators.append(
                    f"{method.upper()} authentication failed"
                )
                score += 3

            elif f"{method}=pass" in auth_text:
                indicators.append(
                    f"{method.upper()} authentication passed"
                )

    else:
        indicators.append(
            "No Authentication-Results header found"
        )
        score += 2

    # 5. Determine risk
    if score >= 6:
        risk = "HIGH"
    elif score >= 3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "valid": True,
        "risk": risk,
        "score": min(score, 100),
        "indicators": indicators
    }
