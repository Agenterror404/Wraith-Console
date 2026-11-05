"""Stealth defaults — make the tool's traffic resemble an ordinary browser so the
operator's OWN detectors (WAF / IDS / bot-detection / logging) are genuinely tested.

Authorized targets only. This is for validating your own detection, not for evading
anyone else's. Everything here is overridable via env so you can dial realism up/down.
"""
import os
import random
import time

# A current, common desktop Chrome UA. httpx/sqlmap/headless-Chromium otherwise send
# tool-identifying User-Agents (python-httpx/x, sqlmap/x, HeadlessChrome) — the first
# thing a detector flags. Override with PENTEST_USER_AGENT.
DEFAULT_UA = os.environ.get(
    "PENTEST_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
)

# Browser-like default headers (set mirrors a real Chrome navigation request).
BASE_HEADERS = {
    "User-Agent": DEFAULT_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Sec-Ch-Ua": '"Chromium";v="129", "Not=A?Brand";v="8", "Google Chrome";v="129"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}

# Optional random delay (seconds) between requests, to avoid burst/rate signatures.
# Off by default (0,0). Set PENTEST_DELAY_MIN/MAX to e.g. 0.3 / 1.5 for slow-and-low.
_DELAY_MIN = float(os.environ.get("PENTEST_DELAY_MIN", "0"))
_DELAY_MAX = float(os.environ.get("PENTEST_DELAY_MAX", "0"))


def headers(extra: dict | None = None) -> dict:
    """Browser-like headers; `extra` (caller-supplied) overrides the defaults."""
    h = dict(BASE_HEADERS)
    if extra:
        h.update(extra)
    return h


def jitter() -> None:
    """Sleep a random interval between requests when a delay window is configured."""
    if _DELAY_MAX > 0:
        time.sleep(random.uniform(_DELAY_MIN, max(_DELAY_MIN, _DELAY_MAX)))


# JS injected into every browser page before load: removes the headless/automation
# tells (navigator.webdriver, empty plugins/languages) that bot-detection checks.
STEALTH_INIT_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
window.chrome = window.chrome || { runtime: {} };
"""
