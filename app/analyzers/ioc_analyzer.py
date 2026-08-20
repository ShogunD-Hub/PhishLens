import re


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    re.IGNORECASE
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

HASH_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
    r"|\b[a-fA-F0-9]{40}\b"
    r"|\b[a-fA-F0-9]{64}\b"
)


def extract_iocs(text: str) -> dict:
    """
    Extract common Indicators of Compromise (IOCs)
    from email content.
    """

    if not text:
        return {
            "urls": [],
            "ip_addresses": [],
            "email_addresses": [],
            "domains": [],
            "hashes": [],
        }

    urls = sorted(set(
        URL_PATTERN.findall(text)
    ))

    ip_addresses = sorted(set(
        IP_PATTERN.findall(text)
    ))

    email_addresses = sorted(set(
        EMAIL_PATTERN.findall(text)
    ))

    hashes = sorted(set(
        HASH_PATTERN.findall(text)
    ))

    domains = extract_domains(
        urls,
        email_addresses
    )

    return {
        "urls": urls,
        "ip_addresses": ip_addresses,
        "email_addresses": email_addresses,
        "domains": domains,
        "hashes": hashes,
    }


def extract_domains(
    urls: list[str],
    email_addresses: list[str]
) -> list[str]:
    """
    Extract domains from URLs and email addresses.
    """

    domains = set()

    for url in urls:

        match = re.match(
            r"https?://([^/:?#]+)",
            url,
            re.IGNORECASE
        )

        if match:
            domains.add(
                match.group(1).lower()
            )

    for email in email_addresses:

        if "@" in email:
            domains.add(
                email.split("@", 1)[1].lower()
            )

    return sorted(domains)
