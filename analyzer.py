import ipaddress
import tldextract
from dataclasses import dataclass
from urllib.parse import urlsplit, SplitResult


@dataclass
class Signal:
    rule: str      # 规则名字，比如 "http"
    points: int    # 加多少风险分
    reason: str    # 给用户看的原因


def check_http(parsed: SplitResult) -> Signal | None:
    if parsed.scheme == "http":
        return Signal(
            rule="http",
            points=15,
            reason="The URL uses HTTP: the connection may be unencrypted."
        )
    return None


def check_at_symbol(parsed: SplitResult) -> Signal | None:
    if parsed.username is not None:
            return Signal(
                rule="at_symbol",
                points=40,
                reason="The URL contains text before @; the real destination is the part after @."
            )
    return None

def check_ip_host(parsed: SplitResult) -> Signal | None:
    if parsed.hostname is None:
        return None
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return None
    return Signal(
        rule="ip_host",
        points=30,
        reason="The URL uses a raw IP address instead of a domain name; legitimate sites rarely do this.",
    )

def check_punycode(parsed: SplitResult) -> Signal | None:
    if parsed.hostname is None:
        return None
    if "xn--" in parsed.hostname:
        return Signal(
            rule="punycode",
            points=30,
            reason="The URL uses punycode; this can be used to spoof domain names."
        )
    return None

def check_brand_impersonation(parsed: SplitResult) -> Signal | None:
    if parsed.hostname is None:
        return None
    ext = tldextract.extract(parsed.hostname)
    registered = f"{ext.domain}.{ext.suffix}"
    for brand, official in OFFICIAL_DOMAINS.items():
        if brand in parsed.hostname and registered not in official:
            return Signal(
                rule="brand_impersonation",
                points=50,
                reason=f"The URL mentions '{brand}', but its registered domain is {registered}, not an official {brand} domain."
            )
    return None

OFFICIAL_DOMAINS = {
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "google.ca"},
    "amazon": {"amazon.com", "amazon.ca"},
    "microsoft": {"microsoft.com"},
    "netflix": {"netflix.com"},
    "scotiabank": {"scotiabank.com"},
    "interac": {"interac.ca"},
}



RULES = [check_http, check_at_symbol, check_ip_host, check_punycode, check_brand_impersonation]

def analyze(url: str) -> dict:
    parsed = urlsplit(url)
    signals = []
    for rule in RULES:
        result = rule(parsed)
        if result is not None:
            signals.append(result)
    score = sum(s.points for s in signals)
    return {
        "destination_host": parsed.hostname,
        "risk_score": score,
        "risk_signals": [s.reason for s in signals],
    }

