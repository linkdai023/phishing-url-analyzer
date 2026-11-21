from urllib.parse import urlsplit

from analyzer import (
    analyze,
    check_at_symbol,
    check_brand_impersonation,
    check_free_hosting,
    check_http,
    check_ip_host,
    check_punycode,
    check_random_subdomain,
    check_sensitive_words,
)


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

def test_brand_inside_longer_word_does_not_trigger():
    result = check_brand_impersonation(urlsplit("https://amazonaws.com"))
    assert result is None

def test_brand_owned_tld_does_not_trigger():
    result = check_brand_impersonation(urlsplit("https://cloud.microsoft"))
    assert result is None

def test_free_hosting_triggers():
    result = check_free_hosting(urlsplit("https://myblog.blogspot.com"))
    assert result is not None
    assert result.points == 20

def test_free_hosting_does_not_trigger():
    result = check_free_hosting(urlsplit("https://example.com"))
    assert result is None

def test_free_hosting_platform_homepage_does_not_trigger():
    result = check_free_hosting(urlsplit("https://www.blogspot.com"))
    assert result is None


def test_random_subdomain_hyphens_triggers():
    result = check_random_subdomain(urlsplit("https://g8zj1-iy5-wn7e-zn8rz.pages.dev"))
    assert result is not None


def test_random_subdomain_digits_triggers():
    result = check_random_subdomain(urlsplit("https://19263840.pages.dev"))
    assert result is not None


def test_readable_subdomain_does_not_trigger():
    result = check_random_subdomain(urlsplit("https://metmuseum.github.io"))
    assert result is None


def test_random_subdomain_ignores_registered_domain():
    # digits in the main domain (not the subdomain) should not count
    result = check_random_subdomain(urlsplit("https://www.shop12345.com"))
    assert result is None


def test_sensitive_word_in_subdomain_triggers():
    result = check_sensitive_words(urlsplit("https://wallet-login.pages.dev"))
    assert result is not None
    assert "wallet" in result.reason and "login" in result.reason


def test_sensitive_word_glued_to_other_text_triggers():
    result = check_sensitive_words(urlsplit("https://facebookteamhelp.blogspot.com"))
    assert result is not None


def test_no_sensitive_word_does_not_trigger():
    result = check_sensitive_words(urlsplit("https://metmuseum.github.io"))
    assert result is None


def test_sensitive_word_only_in_registered_domain_does_not_trigger():
    # the word must be in the subdomain; the registered domain is checked by other rules
    result = check_sensitive_words(urlsplit("https://www.securedrop.org"))
    assert result is None
