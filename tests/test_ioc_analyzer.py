from app.analyzers.ioc_analyzer import extract_iocs


def test_extract_urls():
    text = "Visit https://example.com/login"

    result = extract_iocs(text)

    assert "https://example.com/login" in result["urls"]


def test_extract_ip_addresses():
    text = "Connection received from 192.168.1.50"

    result = extract_iocs(text)

    assert "192.168.1.50" in result["ip_addresses"]


def test_extract_email_addresses():
    text = "Contact attacker@example.com"

    result = extract_iocs(text)

    assert "attacker@example.com" in result["email_addresses"]


def test_extract_domains():
    text = (
        "Visit https://evil-example.com/login "
        "or contact attacker@example.com"
    )

    result = extract_iocs(text)

    assert "evil-example.com" in result["domains"]
    assert "example.com" in result["domains"]


def test_extract_hashes():
    text = (
        "Malware hash: "
        "d41d8cd98f00b204e9800998ecf8427e"
    )

    result = extract_iocs(text)

    assert (
        "d41d8cd98f00b204e9800998ecf8427e"
        in result["hashes"]
    )


def test_empty_input():

    result = extract_iocs("")

    assert result == {
        "urls": [],
        "ip_addresses": [],
        "email_addresses": [],
        "domains": [],
        "hashes": [],
    }
