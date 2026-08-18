from app.analyzers.url_analyzer import (
    extract_urls,
    analyze_urls
)


def test_extract_urls():
    text = """
    Please visit https://example.com/login
    and verify your account.
    """

    urls = extract_urls(text)

    assert "https://example.com/login" in urls


def test_ip_based_url():

    result = analyze_urls(
        "Click https://192.168.1.100/login"
    )

    assert result["score"] >= 20


def test_url_shortener():

    result = analyze_urls(
        "Click https://bit.ly/example"
    )

    assert result["score"] >= 10


def test_normal_url():

    result = analyze_urls(
        "Visit https://www.example.com"
    )

    assert result["score"] == 0
