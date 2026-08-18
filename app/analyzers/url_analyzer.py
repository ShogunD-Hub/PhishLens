import re
from urllib.parse import urlparse


# Known URL shortening services
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
}


# Suspicious top-level domains
SUSPICIOUS_TLDS = {
    ".click",
    ".country",
    ".download",
    ".gq",
    ".icu",
    ".live",
    ".monster",
    ".online",
    ".tk",
    ".top",
    ".work",
}


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)


def extract_urls(text: str) -> list[str]:
    """
    Extract HTTP and HTTPS URLs from email content.
    """

    if not text:
        return []

    urls = URL_PATTERN.findall(text)

    # Remove common punctuation attached to URLs
    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,!?;:)")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def analyse_url(url: str) -> list[dict]:
    """
    Analyse a single URL for suspicious characteristics.
    """

    indicators = []

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return indicators

        hostname = hostname.lower()

        # -------------------------------------------------
        # 1. IP address instead of domain
        # -------------------------------------------------

        ip_pattern = re.compile(
            r"^(?:\d{1,3}\.){3}\d{1,3}$"
        )

        if ip_pattern.match(hostname):
            indicators.append({
                "type": "ip_based_url",
                "severity": "high",
                "score": 20,
                "description": "URL uses an IP address instead of a domain name."
            })

        # -------------------------------------------------
        # 2. URL shortener
        # -------------------------------------------------

        if hostname in URL_SHORTENERS:
            indicators.append({
                "type": "url_shortener",
                "severity": "medium",
                "score": 10,
                "description": "URL uses a known URL shortening service."
            })

        # -------------------------------------------------
        # 3. Suspicious TLD
        # -------------------------------------------------

        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                indicators.append({
                    "type": "suspicious_tld",
                    "severity": "medium",
                    "score": 10,
                    "description": f"Domain uses a potentially suspicious TLD: {tld}"
                })
                break

        # -------------------------------------------------
        # 4. Excessive subdomains
        # -------------------------------------------------

        domain_parts = hostname.split(".")

        if len(domain_parts) >= 5:
            indicators.append({
                "type": "excessive_subdomains",
                "severity": "medium",
                "score": 10,
                "description": "URL contains an unusually large number of subdomains."
            })

        # -------------------------------------------------
        # 5. @ symbol in URL
        # -------------------------------------------------

        if "@" in url:
            indicators.append({
                "type": "url_obfuscation",
                "severity": "high",
                "score": 20,
                "description": "URL contains an @ symbol which can be used to obscure the destination."
            })

        # -------------------------------------------------
        # 6. Very long URL
        # -------------------------------------------------

        if len(url) > 150:
            indicators.append({
                "type": "long_url",
                "severity": "low",
                "score": 5,
                "description": "URL is unusually long and may contain tracking or obfuscation."
            })

        # -------------------------------------------------
        # 7. Suspicious keywords
        # -------------------------------------------------

        suspicious_keywords = [
            "login",
            "verify",
            "account",
            "password",
            "secure",
            "update",
            "payment",
            "invoice",
        ]

        matched_keywords = [
            keyword
            for keyword in suspicious_keywords
            if keyword in url.lower()
        ]

        if len(matched_keywords) >= 2:
            indicators.append({
                "type": "suspicious_url_keywords",
                "severity": "medium",
                "score": 10,
                "description": "URL contains multiple keywords commonly associated with phishing pages."
            })

    except ValueError:
        indicators.append({
            "type": "malformed_url",
            "severity": "medium",
            "score": 10,
            "description": "URL could not be parsed correctly."
        })

    return indicators


def analyze_urls(text: str) -> dict:
    """
    Extract and analyse all URLs found in email content.
    """

    urls = extract_urls(text)

    all_indicators = []
    total_score = 0

    for url in urls:

        indicators = analyse_url(url)

        for indicator in indicators:

            indicator["url"] = url

            all_indicators.append(indicator)

            total_score += indicator["score"]

    # Prevent URL analysis from contributing more than 100 points
    total_score = min(total_score, 100)

    return {
        "score": total_score,
        "urls_found": len(urls),
        "urls": urls,
        "indicators": all_indicators
    }
