
import re


def analyze_sender(email):
    """
    Analyze an email address for suspicious characteristics.
    This is heuristic analysis, not proof of sender identity.
    """

    indicators = []
    score = 0

    email = email.strip()

    email_pattern = (
        r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    )

    if not re.match(email_pattern, email):
        return {
            "valid": False,
            "risk": "HIGH",
            "score": 100,
            "indicators": ["Invalid email address format"]
        }

    username, domain = email.rsplit("@", 1)

    # 1. Check unusually long domains
    if len(domain) > 40:
        indicators.append("Unusually long sender domain")
        score += 2

    # 2. Check excessive hyphens
    if domain.count("-") >= 3:
        indicators.append("Domain contains excessive hyphens")
        score += 2

    # 3. Check suspicious patterns in the username
    if re.search(r"\d{6,}", username):
        indicators.append(
            "Sender username contains an unusually long number sequence"
        )
        score += 1

    if re.search(r"(.)\1{4,}", username):
        indicators.append(
            "Sender username contains repeated characters"
        )
        score += 1

    # 4. Determine risk
    if score >= 4:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "valid": True,
        "risk": risk,
        "score": score,
        "indicators": indicators
    }
