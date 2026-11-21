"""Look up when a domain was registered, using RDAP.

RDAP is the official, JSON-based successor of WHOIS. rdap.org forwards each
query to the registry that is responsible for the domain's TLD.

Results are cached in data/rdap_cache.json so the same domain is only asked once.
"""

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CACHE_PATH = Path(__file__).parent / "data" / "rdap_cache.json"
TIMEOUT_SECONDS = 8
MIN_SECONDS_BETWEEN_REQUESTS = 1.0  # be polite: rdap.org rate-limits fast clients
RETRY_WAIT_SECONDS = 10

_last_request_time = 0.0

_cache: dict[str, str | None] | None = None


def _load_cache() -> dict[str, str | None]:
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(CACHE_PATH.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            _cache = {}
    return _cache


def _save_cache() -> None:
    CACHE_PATH.parent.mkdir(exist_ok=True)
    CACHE_PATH.write_text(json.dumps(_cache, indent=1, sort_keys=True))


def _parse_date(text: str) -> datetime:
    date = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date


def _query_rdap(domain: str, retry: bool = True):
    """Return the RDAP JSON, "not_found" for a 404, or None for a temporary failure."""
    global _last_request_time
    wait = MIN_SECONDS_BETWEEN_REQUESTS - (time.monotonic() - _last_request_time)
    if wait > 0:
        time.sleep(wait)
    _last_request_time = time.monotonic()

    request = urllib.request.Request(
        f"https://rdap.org/domain/{domain}",
        headers={
            "Accept": "application/rdap+json",
            "User-Agent": "phishing-url-analyzer (student learning project)",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return "not_found"  # the registry answered: no such record
        if error.code == 429 and retry:
            time.sleep(RETRY_WAIT_SECONDS)  # "too many requests": wait, then try once more
            return _query_rdap(domain, retry=False)
        return None  # other server errors are temporary
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None  # network problem


def fetch_registration_date(domain: str) -> datetime | None:
    """Return when `domain` was registered, or None if it cannot be found."""
    cache = _load_cache()
    if domain in cache:
        value = cache[domain]
        return _parse_date(value) if value else None

    data = _query_rdap(domain)
    if data is None:
        return None  # temporary problem: not cached, try again next time
    if data == "not_found":
        cache[domain] = None
        _save_cache()
        return None

    date = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration" and "eventDate" in event:
            date = _parse_date(event["eventDate"])
            break

    cache[domain] = date.isoformat() if date else None
    _save_cache()
    return date
