
import re


def analyze_content(content):

    indicators = []
    score = 0

    # Convert email content to lowercase
    text = content.lower()

    # 1. Detect urgency and pressure
    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "limited time",
        "account suspended",
        "account blocked"
    ]

    for word in urgency_words:
        if word in text:
            indicators.append(
                f"Urgency or pressure detected: {word}"
            )
            score += 1

    # 2. Detect requests for sensitive information
    sensitive_words = [
        "password",
        "pin",
        "bank details",
        "credit card",
        "verification code",
        "one-time password",
        "otp",
        "security code"
    ]

    for word in sensitive_words:
        if word in text:
            indicators.append(
                f"Sensitive information mentioned: {word}"
            )
            score += 2

    # 3. Detect financial manipulation
    financial_words = [
        "transfer money",
        "send money",
        "payment required",
        "claim your prize",
        "refund pending",
        "confirm your payment"
    ]

    for word in financial_words:
        if word in text:
            indicators.append(
                f"Financial manipulation indicator: {word}"
            )
            score += 2

    # 4. Detect suspicious verification language
    verification_words = [
        "verify your account",
        "confirm your identity",
        "update your account",
        "validate your account",
        "login to restore"
    ]

    for word in verification_words:
        if word in text:
            indicators.append(
                f"Suspicious verification language: {word}"
            )
            score += 2

    # 5. Detect excessive exclamation marks
    if len(re.findall(r"!{2,}", content)) > 0:
        indicators.append(
            "Excessive exclamation marks detected"
        )
        score += 1

    # 6. Calculate risk level
    if score >= 6:
        risk = "HIGH"

    elif score >= 3:
        risk = "MEDIUM"

    else:
        risk = "LOW"

    return {
        "risk": risk,
        "score": min(score, 100),
        "indicators": indicators
    }
