import re
from email.utils import parseaddr


# Common free email providers.
# These aren't malicious by themselves, but can be suspicious
# when used to impersonate an organisation.
FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}


# Domains commonly associated with URL/email infrastructure
# that may deserve additional investigation.
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


IP_ADDRESS_PATTERN = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)


def extract_email_address(sender: str) -> str:
    """
    Extract the email address from a sender field.

    Supports formats such as:
        security@example.com
        Microsoft Security <security@example.com>
    """

    _, email_address = parseaddr(sender)

    return email_address.lower().strip()


def extract_display_name(sender: str) -> str:
    """
    Extract the display name from a sender field.
    """

    display_name, _ = parseaddr(sender)

    return display_name.strip()


def get_domain(email_address: str) -> str:
    """
    Extract the domain portion of an email address.
    """

    if "@" not in email_address:
        return ""

    return email_address.split("@", 1)[1].lower()


def analyse_sender(
    sender: str,
    reply_to: str | None = None
) -> dict:
    """
    Analyse sender information for common phishing indicators.
    """

    indicators = []
    score = 0

    sender_email = extract_email_address(sender)
    sender_name = extract_display_name(sender)

    if not sender_email or "@" not in sender_email:
        return {
            "score": 20,
            "sender": sender_email,
            "display_name": sender_name,
            "domain": "",
            "indicators": [
                {
                    "type": "invalid_sender",
                    "severity": "high",
                    "score": 20,
                    "description": "Sender address is missing or malformed."
                }
            ]
        }

    sender_domain = get_domain(sender_email)

    # -------------------------------------------------
    # 1. Sender / Reply-To mismatch
    # -------------------------------------------------

    if reply_to:
        reply_email = extract_email_address(reply_to)

        if reply_email and reply_email != sender_email:
            reply_domain = get_domain(reply_email)

            if reply_domain != sender_domain:
                indicators.append({
                    "type": "reply_to_mismatch",
                    "severity": "high",
                    "score": 20,
                    "description": (
                        "Reply-To address uses a different domain "
                        "from the sender address."
                    )
                })

                score += 20

    # -------------------------------------------------
    # 2. Free email provider
    # -------------------------------------------------

    if sender_domain in FREE_EMAIL_PROVIDERS:
        indicators.append({
            "type": "free_email_provider",
            "severity": "low",
            "score": 5,
            "description": (
                "Sender uses a free email provider rather than "
                "an organisation-specific domain."
            )
        })

        score += 5

    # -------------------------------------------------
    # 3. IP address as sender domain
    # -------------------------------------------------

    if IP_ADDRESS_PATTERN.match(sender_domain):
        indicators.append({
            "type": "ip_based_sender",
            "severity": "high",
            "score": 20,
            "description": (
                "Sender domain is an IP address rather than "
                "a conventional domain name."
            )
        })

        score += 20

    # -------------------------------------------------
    # 4. Suspicious TLD
    # -------------------------------------------------

    for tld in SUSPICIOUS_TLDS:
        if sender_domain.endswith(tld):
            indicators.append({
                "type": "suspicious_sender_tld",
                "severity": "medium",
                "score": 10,
                "description": (
                    f"Sender domain uses a potentially suspicious "
                    f"TLD: {tld}"
                )
            })

            score += 10
            break

    # -------------------------------------------------
    # 5. Excessive subdomains
    # -------------------------------------------------

    domain_parts = sender_domain.split(".")

    if len(domain_parts) >= 5:
        indicators.append({
            "type": "excessive_subdomains",
            "severity": "medium",
            "score": 10,
            "description": (
                "Sender domain contains an unusually large "
                "number of subdomains."
            )
        })

        score += 10

    # -------------------------------------------------
    # 6. Suspicious characters in domain
    # -------------------------------------------------

    if "_" in sender_domain:
        indicators.append({
            "type": "suspicious_domain_character",
            "severity": "medium",
            "score": 10,
            "description": (
                "Sender domain contains an underscore, "
                "which is unusual for a standard domain name."
            )
        })

        score += 10

    # -------------------------------------------------
    # 7. Display-name impersonation indicators
    # -------------------------------------------------

    organisation_keywords = [
        "microsoft",
        "apple",
        "google",
        "amazon",
        "paypal",
        "facebook",
        "instagram",
        "linkedin",
        "bank",
        "security",
        "support",
        "admin",
    ]

    if sender_name:
        display_name_lower = sender_name.lower()

        matched_keywords = [
            keyword
            for keyword in organisation_keywords
            if keyword in display_name_lower
        ]

        if matched_keywords and sender_domain in FREE_EMAIL_PROVIDERS:
            indicators.append({
                "type": "display_name_impersonation",
                "severity": "high",
                "score": 20,
                "description": (
                    "Sender display name references an organisation "
                    "but uses a free email provider."
                )
            })

            score += 20

    return {
        "score": min(score, 100),
        "sender": sender_email,
        "display_name": sender_name,
        "domain": sender_domain,
        "indicators": indicators
    }
