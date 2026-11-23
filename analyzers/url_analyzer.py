
import ipaddress
import re
from urllib.parse import urlsplit


def analyze_url(url):
    """
    Analyze URL characteristics using defensive heuristics.
    Does not visit or connect to the supplied URL.
    """

    indicators = []
    score = 0

    url = url.strip()

    # 1. Basic URL validation
    if not url or any(char.isspace() for char in url):
        return {
            "valid": False,
            "risk": "HIGH",
            "score": 100,
            "indicators": ["Invalid URL structure"]
        }

    # 2. Add an assumed HTTPS scheme if missing
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlsplit(url)

        scheme = parsed.scheme.lower()
        hostname = parsed.hostname

        if scheme not in ("http", "https") or not hostname:
            raise ValueError("Unsupported URL structure")

        # Validate port syntax and range
        _ = parsed.port

    except ValueError:
        return {
            "valid": False,
            "risk": "HIGH",
            "score": 100,
            "indicators": ["Malformed or unsupported URL"]
        }

    hostname = hostname.lower().rstrip(".")

    # 3. Check IP addresses
    try:
        ipaddress.ip_address(hostname)

        indicators.append(
            "URL uses an IP address instead of a domain"
        )
        score += 3

    except ValueError:

        # 4. Validate domain hostname structure
        labels = hostname.split(".")

        valid_hostname = (
            len(hostname) <= 253
            and len(labels) >= 2
            and all(
                label
                and len(label) <= 63
                and re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label
                )
                for label in labels
            )
        )

        if not valid_hostname:
            return {
                "valid": False,
                "risk": "HIGH",
                "score": 100,
                "indicators": [
                    "Invalid hostname structure"
                ]
            }

    # 5. Check embedded user information
    if parsed.username is not None or parsed.password is not None:
        indicators.append(
            "URL contains embedded user information"
        )
        score += 4

    # 6. Check punycode domains
    if "xn--" in hostname:
        indicators.append(
            "Domain contains internationalized encoding (punycode)"
        )
        score += 2

    # 7. Check URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "ow.ly"
    ]

    if hostname in shorteners:
        indicators.append(
            "URL uses a shortening service"
        )
        score += 1

    # 8. Check insecure HTTP
    if scheme == "http":
        indicators.append(
            "URL does not use HTTPS"
        )
        score += 1

    # 9. Check URL length
    if len(url) > 200:
        indicators.append(
            "Unusually long URL"
        )
        score += 1

    # 10. Determine risk
    if score >= 4:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "valid": True,
        "risk": risk,
        "score": min(score, 100),
        "indicators": indicators
    }
