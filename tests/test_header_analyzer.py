from app.analyzers.header_analyzer import analyze_headers


def test_reply_to_mismatch():
    headers = {
        "sender": "Microsoft Security <security@microsoft.com>",
        "reply_to": "attacker@evil.com",
        "return_path": "<security@microsoft.com>",
        "subject": "Urgent Account Verification",
        "message_id": "<12345@example.com>",
    }

    result = analyze_headers(headers)

    assert result["reply_to_mismatch"] is True
    assert result["risk_score"] > 0


def test_matching_reply_to():
    headers = {
        "sender": "Microsoft Security <security@microsoft.com>",
        "reply_to": "security@microsoft.com",
        "return_path": "<security@microsoft.com>",
        "subject": "Security Notification",
        "message_id": "<12345@microsoft.com>",
    }

    result = analyze_headers(headers)

    assert result["reply_to_mismatch"] is False
    assert result["risk_score"] == 0

    
