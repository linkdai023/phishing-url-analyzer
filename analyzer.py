import ipaddress
from datetime import datetime, timezone
import tldextract
from dataclasses import dataclass
from urllib.parse import urlsplit, SplitResult

from domain_age import fetch_registration_date


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

def hostname_tokens(hostname: str) -> list[str]:
    return hostname.replace("-", ".").split(".")

def check_brand_impersonation(parsed: SplitResult) -> Signal | None:
    if parsed.hostname is None:
        return None
    ext = tldextract.extract(parsed.hostname)
    registered = f"{ext.domain}.{ext.suffix}"
    tokens = hostname_tokens(parsed.hostname) 
    for brand, official in OFFICIAL_DOMAINS.items():
        if brand in tokens and registered not in official and ext.suffix != brand:
            return Signal(
                rule="brand_impersonation",
                points=50,
                reason=f"The URL mentions '{brand}', but its registered domain is {registered}, not an official {brand} domain."
            )
    return None

def check_free_hosting(parsed: SplitResult) -> Signal | None:
    if parsed.hostname is None:
        return None
    ext = tldextract.extract(parsed.hostname)
    registered = f"{ext.domain}.{ext.suffix}"
    if registered in FREE_HOSTING and ext.subdomain not in ("", "www"):
        return Signal(
            rule="free_hosting",
            points=20,
            reason=f"The site is hosted on a free platform ({registered}). This is common for both personal sites and phishing, so it is a weak signal on its own.",
        )
    return None

def check_random_subdomain(parsed: SplitResult) -> Signal | None:
    if parsed.hostname is None:
        return None
    sub = tldextract.extract(parsed.hostname).subdomain
    hyphens = sub.count("-")
    digits = sum(c.isdigit() for c in sub)
    if hyphens >= 3 or digits >= 4:
        return Signal(
            rule="random_subdomain",
            points=20,
            reason=f"The subdomain looks auto-generated ({hyphens} hyphens, {digits} digits). Some personal sites also use names with numbers, so this is a weak signal on its own.",
        )
    return None


def check_sensitive_words(parsed: SplitResult) -> Signal | None:
    if parsed.hostname is None:
        return None
    sub = tldextract.extract(parsed.hostname).subdomain.lower()
    found = [w for w in SENSITIVE_WORDS if w in sub]
    if found:
        return Signal(
            rule="sensitive_words",
            points=20,
            reason=f"The subdomain contains words often used in scams: {', '.join(found)}. Anyone can put these words in a subdomain.",
        )
    return None


def check_domain_age(parsed: SplitResult) -> Signal | None:
    if parsed.hostname is None:
        return None
    ext = tldextract.extract(parsed.hostname)
    if not ext.suffix:
        return None  # e.g. an IP address: there is no registered domain to look up
    registered = f"{ext.domain}.{ext.suffix}"
    if registered in FREE_HOSTING:
        return None  # the platform's age says nothing about the site on it

    created = fetch_registration_date(registered)
    if created is None:
        return Signal(
            rule="domain_age_unknown",
            points=0,
            reason=f"Could not find when {registered} was registered. Unknown does not mean safe.",
        )
    age_days = (datetime.now(timezone.utc) - created).days
    if age_days < 30:
        return Signal(
            rule="new_domain",
            points=30,
            reason=f"{registered} was registered only {age_days} days ago. Scam sites often use brand-new domains.",
        )
    if age_days < 180:
        return Signal(
            rule="young_domain",
            points=15,
            reason=f"{registered} was registered {age_days} days ago (less than 6 months).",
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

FREE_HOSTING = {
    "pages.dev", "blogspot.com", "github.io", "vercel.app",
    "workers.dev", "web.app", "firebaseapp.com", "netlify.app",
    "weebly.com", "wixsite.com",
}

# Words that scam sites put in subdomains. Two groups:
#  - actions that pressure the user (log in, verify, claim a prize)
#  - brands that are commonly impersonated
# Chosen from general knowledge of phishing, not tuned on the test data.
SENSITIVE_WORDS = [
    "login", "logon", "signin", "verify", "verification", "secure", "account",
    "update", "recover", "unlock", "confirm", "support", "wallet", "billing",
    "claim", "reward", "bonus", "prize", "giveaway", "winner", "airdrop",
    "paypal", "apple", "icloud", "google", "gmail", "amazon", "microsoft",
    "outlook", "office365", "netflix", "facebook", "instagram", "whatsapp",
    "telegram", "tiktok", "roblox", "steam", "shopee", "lazada", "binance",
    "coinbase", "metamask", "trezor", "ledger", "dhl", "fedex", "usps",
    "canadapost", "interac", "scotiabank",
]

RULES = [check_http, check_at_symbol, check_ip_host, check_punycode, check_brand_impersonation, check_free_hosting,
         check_random_subdomain, check_sensitive_words,
         check_domain_age]

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

