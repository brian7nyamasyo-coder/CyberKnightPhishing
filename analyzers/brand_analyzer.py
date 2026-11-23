
import json
from pathlib import Path
from urllib.parse import urlsplit


BRAND_DATABASE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "brand_domains.json"
)


def load_brand_domains():
    """Load known brand domains from the JSON database."""

    try:
        with open(BRAND_DATABASE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (OSError, json.JSONDecodeError):
        return {}


def analyze_brand(url):
    """
    Identify known brand names appearing in a URL
    outside their registered reference domains.

    This is a heuristic indicator, not proof of fraud.
    """

    indicators = []
    score = 0

    brands = load_brand_domains()

    # Normalize URLs without an explicit scheme.
    url = url.strip()

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname

        if not hostname:
            return {
                "risk": "LOW",
                "score": 0,
                "indicators": []
            }

        hostname = hostname.lower().rstrip(".")

    except ValueError:
        return {
            "risk": "LOW",
            "score": 0,
            "indicators": []
        }

    for brand, legitimate_domains in brands.items():

        brand = brand.lower()

        hostname_labels = hostname.split(".")

        brand_mentioned = any(
            brand in label
            for label in hostname_labels
        )

        if not brand_mentioned:
            continue

        legitimate = any(
            hostname == domain.lower()
            or hostname.endswith("." + domain.lower())
            for domain in legitimate_domains
        )

        if not legitimate:
            indicators.append(
                f"Brand name '{brand}' appears outside its "
                "reference domains"
            )
            score += 4

    if score >= 4:
        risk = "HIGH"
    else:
        risk = "LOW"

    return {
        "risk": risk,
        "score": min(score, 100),
        "indicators": indicators
    }
