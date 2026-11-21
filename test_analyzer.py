from urllib.parse import urlsplit

from analyzer import analyze,check_http, check_at_symbol, check_ip_host, check_punycode, check_brand_impersonation


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

def test_ip_host_triggers():
    result = check_ip_host(urlsplit("http://192.168.1.1"))
    assert result is not None
    assert result.points == 30

def test_ip_host_does_not_trigger():
    result = check_ip_host(urlsplit("https://example.com"))
    assert result is None   
    
def test_analyze_combines_all_rules():
    result = analyze("http://192.168.1.1/login")
    assert result["risk_score"] == 45

def test_punycode_triggers():
    result = check_punycode(urlsplit("http://xn--example.com"))
    assert result is not None
    assert result.points == 30

def test_punycode_does_not_trigger():
    result = check_punycode(urlsplit("https://example.com"))
    assert result is None

def test_punycode_in_subdomain_triggers():
    result = check_punycode(urlsplit("https://www.xn--pple-43d.com"))
    assert result is not None

def test_brand_impersonation_triggers():
    result = check_brand_impersonation(urlsplit("http://paypal-secure.com"))
    assert result is not None
    assert result.points == 50

def test_brand_impersonation_triggers():
    result = check_brand_impersonation(urlsplit("http://paypal-verify.xyz"))
    assert result is not None
    assert result.points == 50

def test_brand_impersonation_does_not_trigger():
    result = check_brand_impersonation(urlsplit("https://paypal.com"))
    assert result is None

def test_brand_impersonation_does_not_trigger():
    result = check_brand_impersonation(urlsplit("https://example.com"))
    assert result is None

def test_brand_impersonation_dash_domain_triggers():
    result = check_brand_impersonation(urlsplit("https://paypal-verify.xyz"))
    assert result is not None


def test_official_brand_domain_does_not_trigger():
    result = check_brand_impersonation(urlsplit("https://www.paypal.com"))
    assert result is None