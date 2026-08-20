import re
from email.utils import parseaddr


def analyze_headers(headers):
    """
    Analyze email headers for common phishing indicators.
    """

    sender = headers.get("sender", "")
    reply_to = headers.get("reply_to", "")
    return_path = headers.get("return_path", "")

    sender_email = parseaddr(sender)[1].lower()
    reply_to_email = parseaddr(reply_to)[1].lower()
    return_path_email = parseaddr(return_path)[1].lower()

    risk_score = 0
    indicators = []

    # Check Reply-To mismatch
    reply_to_mismatch = (
        bool(sender_email)
        and bool(reply_to_email)
        and sender_email != reply_to_email
    )

    if reply_to_mismatch:
        risk_score += 30
        indicators.append("Reply-To address differs from sender address")

    # Check Return-Path mismatch
    return_path_mismatch = (
        bool(sender_email)
        and bool(return_path_email)
        and sender_email != return_path_email
    )

    if return_path_mismatch:
        risk_score += 20
        indicators.append("Return-Path differs from sender address")

    return {
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "risk_score": risk_score,
        "indicators": indicators,
    }
