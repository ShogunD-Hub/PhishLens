from app.api.analyze import EmailRequest, analyze_email


def test_analyze_email_includes_header_analysis():
    email = EmailRequest(
        sender="Microsoft Security <security@microsoft.com>",
        reply_to="attacker@evil.com",
        subject="Urgent Account Verification",
        body="Please verify your account immediately.",
    )

    result = analyze_email(email)

    assert "header" in result["analysis"]

    assert result["analysis"]["header"]["reply_to_mismatch"] is True

    assert result["risk_assessment"]["risk_score"] > 0
