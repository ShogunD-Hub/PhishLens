import re


# Phishing indicators and their associated risk scores
PHISHING_PATTERNS = {
    "urgent_language": {
        "patterns": [
            r"\burgent\b",
            r"\bimmediately\b",
            r"\bact now\b",
            r"\baction required\b",
            r"\bfinal warning\b",
            r"\bexpires?\b",
            r"\bwithin \d+ hours?\b",
        ],
        "score": 10,
        "severity": "medium",
        "description": "Email contains language designed to create urgency or pressure."
    },

    "credential_request": {
        "patterns": [
            r"\bpassword\b",
            r"\busername\b",
            r"\bverify your account\b",
            r"\bconfirm your identity\b",
            r"\blogin\b",
            r"\bsign in\b",
            r"\bcredentials?\b",
        ],
        "score": 20,
        "severity": "high",
        "description": "Email appears to request credentials or account verification."
    },

    "payment_request": {
        "patterns": [
            r"\bmake a payment\b",
            r"\bsend payment\b",
            r"\bbank transfer\b",
            r"\bwire transfer\b",
            r"\binvoice\b",
            r"\bpayment required\b",
            r"\bpay immediately\b",
        ],
        "score": 15,
        "severity": "high",
        "description": "Email contains language associated with payment or financial requests."
    },

    "threat_language": {
        "patterns": [
            r"\baccount will be closed\b",
            r"\baccount will be suspended\b",
            r"\byour account has been suspended\b",
            r"\blegal action\b",
            r"\bpenalty\b",
            r"\byou will lose access\b",
        ],
        "score": 10,
        "severity": "medium",
        "description": "Email contains threatening or intimidating language."
    }
}


def analyze_content(text: str) -> dict:
    """
    Analyse email content for common phishing indicators.

    Returns:
        dict containing the risk score and detected indicators.
    """

    if not text:
        return {
            "score": 0,
            "indicators": []
        }

    text = text.lower()

    score = 0
    indicators = []

    for indicator_type, indicator_data in PHISHING_PATTERNS.items():

        matches = []

        for pattern in indicator_data["patterns"]:
            if re.search(pattern, text):
                matches.append(pattern)

        if matches:
            score += indicator_data["score"]

            indicators.append({
                "type": indicator_type,
                "severity": indicator_data["severity"],
                "score": indicator_data["score"],
                "description": indicator_data["description"],
                "matches": len(matches)
            })

    # Prevent the content analyser from exceeding 100
    score = min(score, 100)

    return {
        "score": score,
        "indicators": indicators
    }
