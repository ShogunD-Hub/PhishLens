from app.analyzers.sender_analyzer import analyse_sender


def test_normal_sender():
    result = analyse_sender(
        "security@company.com"
    )

    assert result["score"] == 0
    assert result["domain"] == "company.com"


def test_reply_to_mismatch():
    result = analyse_sender(
        "security@company.com",
        "attacker@evil.com"
    )

    assert result["score"] >= 20


def test_free_email_provider():
    result = analyse_sender(
        "security@gmail.com"
    )

    assert result["score"] >= 5


def test_display_name_impersonation():
    result = analyse_sender(
        "Microsoft Security <security@gmail.com>"
    )

    assert result["score"] >= 25


def test_ip_based_sender():
    result = analyse_sender(
        "security@192.168.1.100"
    )

    assert result["score"] >= 20
