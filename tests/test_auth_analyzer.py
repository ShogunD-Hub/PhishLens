from app.analyzers.auth_analyzer import analyze_authentication


def test_all_authentication_pass():

    header = (
        "mx.example.com; "
        "spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; "
        "dmarc=pass header.from=example.com"
    )

    result = analyze_authentication(header)

    assert result["available"] is True
    assert result["results"]["spf"] == "pass"
    assert result["results"]["dkim"] == "pass"
    assert result["results"]["dmarc"] == "pass"
    assert result["score"] == 0


def test_authentication_failures():

    header = (
        "mx.example.com; "
        "spf=fail smtp.mailfrom=evil.com; "
        "dkim=fail; "
        "dmarc=fail header.from=company.com"
    )

    result = analyze_authentication(header)

    assert result["results"]["spf"] == "fail"
    assert result["results"]["dkim"] == "fail"
    assert result["results"]["dmarc"] == "fail"
    assert result["score"] == 45


def test_partial_authentication():

    header = (
        "mx.example.com; "
        "spf=pass smtp.mailfrom=example.com; "
        "dkim=fail; "
        "dmarc=pass header.from=example.com"
    )

    result = analyze_authentication(header)

    assert result["results"]["spf"] == "pass"
    assert result["results"]["dkim"] == "fail"
    assert result["results"]["dmarc"] == "pass"
    assert result["score"] == 15


def test_missing_header():

    result = analyze_authentication(None)

    assert result["available"] is False
    assert result["score"] == 0


def test_empty_header():

    result = analyze_authentication("")

    assert result["available"] is False
    assert result["score"] == 0
