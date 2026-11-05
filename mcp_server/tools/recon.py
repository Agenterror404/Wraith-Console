"""Recon: fingerprint + path enumeration. Read-only probing of the in-scope target."""
import os

import httpx

from .. import safehttp, stealth
from ..config import HTTP_TIMEOUT
from ..scope_guard import OutOfScope, check

# Bundled wordlist (Opus baseline + qwen-expanded), used by default.
_WORDLIST = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "common.txt")
SEED_PATHS = ["/", "/robots.txt", "/sitemap.xml", "/rest", "/api", "/ftp", "/.well-known/security.txt"]


def _default_paths() -> list[str]:
    try:
        with open(_WORDLIST) as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except OSError:
        return SEED_PATHS


def _title_of(body: str) -> str:
    low = body.lower()
    if "<title>" not in low:
        return ""
    s = low.index("<title>") + 7
    e = low.find("</title>", s)
    return body[s : (e if e != -1 else s + 200)].strip()[:200]


def _detect_challenge(status: int, headers, title: str, body: str) -> list[str]:
    """Recognize a bot/WAF challenge interstitial, so HTTP-only recon output is labeled honestly
    instead of being mistaken for the real app (e.g. Vercel's 'Security Checkpoint')."""
    srv = (headers.get("server", "") or "").lower()
    t = (title or "").lower()
    b = (body or "")[:4000].lower()
    hk = " ".join(k.lower() for k in headers.keys())
    sig = []
    if "vercel security checkpoint" in t or (srv == "vercel" and status in (429, 503)):
        sig.append("Vercel Security Checkpoint (bot/DDoS challenge)")
    if ("just a moment" in t or "attention required" in t or "cf-mitigated" in hk
            or "cf-chl" in b or "challenge-platform" in b):
        sig.append("Cloudflare challenge")
    if "incapsula" in b or "_incap_" in hk or "imperva" in srv:
        sig.append("Imperva/Incapsula challenge")
    if status in (429, 503) and not sig:
        sig.append(f"possible WAF / rate-limit (HTTP {status})")
    return sig


def recon_http(target: str) -> dict:
    """Fetch the target root and report server fingerprint (status, headers, title). Flags a
    bot/WAF challenge (Vercel/Cloudflare/etc.) so the result isn't mistaken for the real app."""
    check(target)
    stealth.jitter()
    # follow_redirects=False: a 3xx to an out-of-scope host must not be chased (H1).
    r = safehttp.get(target, timeout=HTTP_TIMEOUT, follow_redirects=False, headers=stealth.headers())
    body = r.text if "text/html" in r.headers.get("content-type", "") else ""
    title = _title_of(body) if body else ""
    out = {
        "status": r.status_code,
        "server": r.headers.get("server", ""),
        "powered_by": r.headers.get("x-powered-by", ""),
        "title": title,
        "headers": dict(r.headers),
    }
    waf = _detect_challenge(r.status_code, r.headers, title, body)
    if waf:
        out["waf"] = waf
        out["note"] = ("Target is behind a bot/WAF challenge — HTTP-only tools (ffuf, gobuster, "
                       "enum_paths, etc.) see the challenge page, not the app, and will report "
                       "false positives. Use browser_recon (real browser) to render the real site.")
    return out


def enum_paths(target: str, wordlist_path: str | None = None) -> dict:
    """Probe seed paths (or a wordlist file) and report which exist. One request per path."""
    check(target)
    if wordlist_path:
        with open(wordlist_path) as f:
            paths = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    else:
        paths = _default_paths()
    import secrets as _secrets
    base = target.rstrip("/")
    found = []
    suppressed = 0
    catch_all = None
    with safehttp.client(target, timeout=HTTP_TIMEOUT, follow_redirects=False, headers=stealth.headers()) as c:
        # Baseline: a path that should NOT exist. If the edge answers it with a "found-like"
        # status (a CDN/WAF catch-all, e.g. Vercel's uniform 403), use (status,len) to drop
        # false positives — otherwise every probed path looks like a hit.
        try:
            stealth.jitter()
            br = c.get(base + "/wraith-probe-" + _secrets.token_hex(8) + "/does-not-exist")
            catch_all = {"status": br.status_code, "len": len(br.content)}  # whatever the edge says to an unknown path
        except httpx.HTTPError:
            pass
        _BLOCK = {401, 403, 429, 503}  # block/challenge statuses the edge may blanket-return
        edge_blocks = bool(catch_all and catch_all["status"] in _BLOCK)
        for p in paths:
            url = base + p
            try:
                check(url)  # re-validate: a wordlist entry must not retarget off-scope (e.g. "@evil.com")
            except OutOfScope:
                continue
            try:
                stealth.jitter()
                r = c.get(url)
                st, ln = r.status_code, len(r.content)
                if not (st < 400 or st in (401, 403)):
                    continue
                # suppress false positives: identical to the catch-all, OR the edge blocks every
                # unknown path (CDN/WAF) and this is just another block/challenge response.
                if catch_all and ((st == catch_all["status"] and ln == catch_all["len"])
                                  or (edge_blocks and st in _BLOCK)):
                    suppressed += 1
                    continue
                found.append({"path": p, "status": st, "len": ln})
            except httpx.HTTPError:
                continue
    out = {"target": target, "checked": len(paths), "found": found}
    if catch_all and (edge_blocks or suppressed):
        out["catch_all"] = catch_all
        out["suppressed"] = suppressed
        out["note"] = (f"Edge blankets unknown paths with HTTP {catch_all['status']} (~{catch_all['len']}b) "
                       f"— a CDN/WAF catch-all; {suppressed} false-positive hit(s) dropped. Path "
                       f"brute-force is unreliable here — use browser_recon with a clearance cookie.")
    return out
