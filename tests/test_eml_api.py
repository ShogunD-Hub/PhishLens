from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_analyze_eml():
    email_content = b"""\
From: Microsoft Security <security@microsoft.com>
Reply-To: attacker@evil.com
Subject: Urgent Account Verification
Return-Path: <security@microsoft.com>
Message-ID: <12345@example.com>

Please verify your account immediately.
"""

    response = client.post(
        "/api/analyze-eml",
        files={
            "file": (
                "suspicious.eml",
                email_content,
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["email"]["sender"] == (
        "Microsoft Security <security@microsoft.com>"
    )

    assert data["email"]["reply_to"] == "attacker@evil.com"

    assert data["email"]["subject"] == "Urgent Account Verification"

    assert "analysis" in data
    assert "header" in data["analysis"]

    assert data["analysis"]["header"]["reply_to_mismatch"] is True

    assert "risk_assessment" in data
    assert data["risk_assessment"]["risk_score"] > 0
