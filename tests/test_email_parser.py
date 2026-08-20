from app.analyzers.email_parser import parse_eml


def test_parse_eml():

    email_content = b"""\
From: Microsoft Security <security@gmail.com>
Reply-To: attacker@evil.com
Subject: Urgent Account Verification
Return-Path: <security@gmail.com>
Message-ID: <12345@example.com>

Please verify your account immediately.
"""

    result = parse_eml(email_content)

    assert result["sender"] == "Microsoft Security <security@gmail.com>"
    assert result["reply_to"] == "attacker@evil.com"
    assert result["subject"] == "Urgent Account Verification"
    assert result["return_path"] == "<security@gmail.com>"
    assert result["message_id"] == "<12345@example.com>"
    assert "verify your account" in result["body"]
