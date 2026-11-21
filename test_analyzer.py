from urllib.parse import urlsplit

from analyzer import check_http, check_at_symbol


def test_http_triggers():
    result = check_http(urlsplit("http://example.com"))
    assert result is not None
    assert result.points == 15


def test_https_does_not_trigger():
    result = check_http(urlsplit("https://example.com"))
    assert result is None

def test_at_symbol_triggers():
    result = check_at_symbol(urlsplit("http://user@example.com"))
    assert result is not None
    assert result.points == 40

def test_at_symbol_does_not_trigger():

    result = check_at_symbol(urlsplit("https://example.com"))
    assert result is None