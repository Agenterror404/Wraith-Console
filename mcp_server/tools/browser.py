"""Headless-Chromium scenarios via Playwright: login/2FA flows and DOM-XSS checks
that need a real DOM. EVERY navigation is scope-checked (not just the start URL),
and screenshot paths are confined to the evidence dir."""
import json
import os
from urllib.parse import urlparse

from .. import stealth
from ..config import HTTP_TIMEOUT, load_scope
from ..scope_guard import OutOfScope, check


# Chromium phones home by default (component/variations updates, safe-browsing,
# domain reliability, hyperlink pings). These flags shut all of that off so the only
# traffic the browser makes is to the scoped target.
_CHROMIUM_ARGS = [
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-sync",
    "--disable-client-side-phishing-detection",
    "--safebrowsing-disable-auto-update",
    "--no-first-run",
    "--no-default-browser-check",
    "--no-pings",
    "--metrics-recording-only",
    "--disable-breakpad",
    "--disable-features=OptimizationHints,Translate,MediaRouter,"
    "AutofillServerCommunication,InterestFeedContentSuggestions",
    # stealth: drop the headless/automation flag bot-detection keys on
    "--disable-blink-features=AutomationControlled",
    # stealth: stop WebRTC from exposing the container's local/tunnel IP via STUN —
    # non-proxied UDP is disabled, so WebRTC can't sidestep the egress path.
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
]

# Context fingerprint matched to your network exit geo. A browser whose timezone / locale /
# geolocation disagree with the exit IP's geo is a classic fingerprint mismatch, so these
# stay aligned with the active exit.
#
# Manual exit selector: ONE knob, PENTEST_EXIT=<city>, sets the browser timezone /
# locale / geolocation to match that city. Align it with wherever your
# traffic actually egresses. Default "chicago".
# To add an exit: add a row to the table below (city -> tz, locale, lat, lon), or
# just set PENTEST_EXIT_TZ/LOCALE/LAT/LON explicitly — those env vars still override.
_EXITS = {
    # city        : (timezone_id,          locale,  lat,      lon)
    "chicago":      ("America/Chicago",     "en-US", 41.8781,  -87.6298),
    "new-york":     ("America/New_York",    "en-US", 40.7128,  -74.0060),
    "dallas":       ("America/Chicago",     "en-US", 32.7767,  -96.7970),
    "los-angeles":  ("America/Los_Angeles", "en-US", 34.0522, -118.2437),
    "miami":        ("America/New_York",    "en-US", 25.7617,  -80.1918),
    "atlanta":      ("America/New_York",    "en-US", 33.7490,  -84.3880),
    "seattle":      ("America/Los_Angeles", "en-US", 47.6062, -122.3321),
    "denver":       ("America/Denver",      "en-US", 39.7392, -104.9903),
    "london":       ("Europe/London",       "en-GB", 51.5074,   -0.1278),
}
_EXIT = os.environ.get("PENTEST_EXIT", "chicago").strip().lower()
_tz, _loc, _lat, _lon = _EXITS.get(_EXIT, _EXITS["chicago"])
# explicit env always wins — covers an exit city not in the table above.
_EXIT_TZ = os.environ.get("PENTEST_EXIT_TZ", _tz)
_EXIT_LOCALE = os.environ.get("PENTEST_EXIT_LOCALE", _loc)
_EXIT_LAT = float(os.environ.get("PENTEST_EXIT_LAT", _lat))
_EXIT_LON = float(os.environ.get("PENTEST_EXIT_LON", _lon))


def exit_info() -> dict:
    """Read-only view of the active egress exit (the Console badge reads this instead of
    reaching into the private module vars). Static for the container's lifetime — the exit
    only changes via PENTEST_EXIT + a compose recreate."""
    return {"city": _EXIT, "tz": _EXIT_TZ, "locale": _EXIT_LOCALE,
            "lat": _EXIT_LAT, "lon": _EXIT_LON}


def _context_opts(browser=None) -> dict:
    """new_context() options: timezone/locale/geo matched to the exit, and a User-Agent that
    MATCHES THE ACTUAL browser (real Chrome major version + the true Linux platform). Faking a
    Windows UA on a Linux chromium desyncs the UA from the client-hints (Sec-CH-UA-Platform:
    Linux) and the JS platform — a tell. Matching reality (and only stripping the "Headless"
    token in headless mode) is self-consistent: a genuine Linux Chrome user is unremarkable."""
    opts = {
        "locale": _EXIT_LOCALE,
        "timezone_id": _EXIT_TZ,
        "geolocation": {"latitude": _EXIT_LAT, "longitude": _EXIT_LON},
        "permissions": ["geolocation"],
    }
    if browser is not None:
        try:
            maj = (browser.version or "").split(".")[0] or "131"
            opts["user_agent"] = (
                f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                f"(KHTML, like Gecko) Chrome/{maj}.0.0.0 Safari/537.36"
            )
        except Exception:
            pass
    return opts


def _sync_playwright():
    """Prefer patchright (patched Chromium — fixes the CDP Runtime.enable leak + webdriver/
    console tells that stock Playwright exposes) when available; fall back to stock Playwright
    so the proven browser path never hard-breaks. PENTEST_BROWSER=playwright forces stock."""
    if os.environ.get("PENTEST_BROWSER", "patchright").lower() != "playwright":
        try:
            from patchright.sync_api import sync_playwright
            return sync_playwright
        except Exception:
            pass
    from playwright.sync_api import sync_playwright
    return sync_playwright


def _oast_name(oast_host: str) -> str:
    """Hostname of an operator-supplied out-of-band listener (scheme/port stripped)."""
    oh = (oast_host or "").strip()
    if not oh:
        return ""
    return (urlparse(oh if "://" in oh else f"//{oh}").hostname or oh).lower()


def _ws_guard_js(oast_host: str = "") -> str:
    """Init script that blocks WebSocket/EventSource to any host not in scope (H3).
    Playwright's request router does not cover WebSockets, so enforce it in-page against
    the real scope allowlist — in-scope channels (incl. the page's own origin) still work.
    If oast_host is set (the per-run listener switch), that one host is also allowed."""
    allowed = []
    for e in load_scope().get("targets", []):
        if isinstance(e, str):
            h, _, p = e.partition(":")
            allowed.append([h.lower(), int(p) if p.isdigit() else None])
        elif isinstance(e, dict):
            port = e.get("port")
            allowed.append([str(e.get("host", "")).lower(), port if isinstance(port, int) else None])
    oast = _oast_name(oast_host)
    if oast:
        allowed.append([oast, None])  # listener on: any port on that host
    data = json.dumps(allowed)
    return (
        "(function(){var A=" + data + ";"
        "function dp(p){p=(p||'').toLowerCase();return (p==='wss:'||p==='https:')?443:((p==='ws:'||p==='http:')?80:0);}"
        "function ok(u){try{var x=new URL(u, location.href);var h=x.hostname.toLowerCase();"
        "var pt=x.port?parseInt(x.port,10):dp(x.protocol);"
        "return A.some(function(e){return e[0]===h&&(e[1]===null||e[1]===pt);});}catch(_){return false;}}"
        "var OW=window.WebSocket;if(OW){window.WebSocket=function(u,p){if(!ok(u))"
        "throw new DOMException('Wraith: WebSocket to out-of-scope host blocked','SecurityError');"
        "return (p===undefined)?new OW(u):new OW(u,p);};window.WebSocket.prototype=OW.prototype;}"
        "var OE=window.EventSource;if(OE){window.EventSource=function(u,c){if(!ok(u))"
        "throw new DOMException('Wraith: EventSource to out-of-scope host blocked','SecurityError');"
        "return (c===undefined)?new OE(u):new OE(u,c);};window.EventSource.prototype=OE.prototype;}"
        "})();"
    )


def _check_nav(url: str) -> str:
    """A navigation target must be http/https AND in scope. Blocks file://, gopher://,
    chrome://, cloud-metadata-by-other-scheme, and any out-of-scope host."""
    scheme = urlparse(url if "://" in url else f"http://{url}").scheme.lower()
    if scheme not in ("http", "https"):
        raise OutOfScope(f"navigation scheme {scheme!r} not allowed: {url!r}")
    check(url)
    return url


def browser_scenario(target: str, steps: list[dict], capture_console: bool = True,
                     oast_host: str = "") -> dict:
    """Drive headless Chromium through `steps`, return final URL, console logs, screenshot path.

    steps: ordered list of {action, ...}. Supported actions:
      {goto: url}  {fill: selector, value: str}  {click: selector}
      {wait: ms}  {eval: js}  {screenshot: name}
    Every `goto` (and the start `target`) is scope-checked and must be http/https.
    `eval` runs only in the page, which is always an in-scope origin.
    oast_host: optional out-of-band listener (the per-run "listener on" switch). When set,
      the page may also reach that one host (HTTP + WebSocket/EventSource) for OAST callbacks;
      empty = strict scope-only.
    """
    oast = _oast_name(oast_host)
    # Pre-validate ALL navigations before launching the browser (fail closed, no partial run).
    _check_nav(target)
    for step in steps:
        if "goto" in step:
            _check_nav(step["goto"])

    try:
        sync_playwright = _sync_playwright()
    except ImportError:
        return {"error": "playwright not installed in sandbox"}

    from ..config import EVIDENCE_DIR

    evdir = EVIDENCE_DIR.resolve()
    console: list[str] = []
    result: dict = {"steps_run": 0, "console": console, "evals": []}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=_CHROMIUM_ARGS)
        context = browser.new_context(**_context_opts(browser))  # real UA, not HeadlessChrome

        def _scope_route(route):
            # Gate EVERY http/https request to scope — covers redirects, link clicks,
            # form posts and eval-driven fetch/navigation, not just explicit goto steps.
            url = route.request.url
            scheme = urlparse(url).scheme.lower()
            if scheme in ("http", "https"):
                if oast and (urlparse(url).hostname or "").lower() == oast:
                    return route.continue_()   # per-run listener switch: this one host allowed
                try:
                    check(url)
                except OutOfScope:
                    return route.abort()
                return route.continue_()
            if scheme in ("data", "blob", "about"):
                return route.continue_()   # inert, no network egress
            return route.abort()           # ws/wss/ftp/other off-target schemes: fail closed (H3)

        context.route("**/*", _scope_route)
        context.add_init_script(_ws_guard_js(oast_host))        # scope-gate WebSocket/EventSource (H3)
        page = context.new_page()
        page.add_init_script(stealth.STEALTH_INIT_JS)           # hide webdriver/automation tells
        if capture_console:
            page.on("console", lambda m: console.append(f"{m.type}: {m.text}"[:500]))
        page.goto(target, timeout=HTTP_TIMEOUT * 1000)
        for step in steps:
            if "goto" in step:
                page.goto(step["goto"], timeout=HTTP_TIMEOUT * 1000)
            elif "fill" in step:
                page.fill(step["fill"], step.get("value", ""))
            elif "click" in step:
                page.click(step["click"])
            elif "wait" in step:
                page.wait_for_timeout(int(step["wait"]))
            elif "eval" in step:
                result["evals"].append(page.evaluate(step["eval"]))
            elif "screenshot" in step:
                # basename only, then confirm the resolved path stays under evidence dir.
                name = os.path.basename(str(step["screenshot"])) or "shot"
                path = (EVIDENCE_DIR / f"{name}.png")
                if evdir != path.resolve().parent:
                    browser.close()
                    return {"refused": True, "reason": "screenshot path escapes evidence dir"}
                page.screenshot(path=str(path))
                result.setdefault("screenshots", []).append(str(path))
            result["steps_run"] += 1
        result["final_url"] = page.url
        browser.close()
    return result


def screenshot(target: str) -> dict:
    """Full-page screenshot of the target via the SAME scope-gated headless Chromium as
    browser_scenario (every request scope-checked; no phone-home). Saved under the evidence
    dir's shots/ folder; returns `screenshot` (the filename), page title and final URL."""
    import re
    import time

    _check_nav(target)
    try:
        sync_playwright = _sync_playwright()
    except ImportError:
        return {"error": "playwright not installed in sandbox"}
    from ..config import EVIDENCE_DIR

    shots = EVIDENCE_DIR / "shots"
    shots.mkdir(parents=True, exist_ok=True)
    host = (urlparse(target if "://" in target else f"//{target}").hostname or "shot")
    name = f"{re.sub(r'[^A-Za-z0-9._-]', '_', host)}-{int(time.time())}.png"
    path = shots / name
    if shots.resolve() != path.resolve().parent:  # basename-only confinement
        return {"refused": True, "reason": "screenshot path escapes evidence dir"}

    def _scope_route(route):
        url = route.request.url
        scheme = urlparse(url).scheme.lower()
        if scheme in ("http", "https"):
            try:
                check(url)
            except OutOfScope:
                return route.abort()
            return route.continue_()
        if scheme in ("data", "blob", "about"):
            return route.continue_()
        return route.abort()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=_CHROMIUM_ARGS)
        try:
            context = browser.new_context(**_context_opts(browser))
            context.route("**/*", _scope_route)
            context.add_init_script(_ws_guard_js(""))
            page = context.new_page()
            page.add_init_script(stealth.STEALTH_INIT_JS)
            page.goto(target, timeout=HTTP_TIMEOUT * 1000)
            page.wait_for_timeout(600)
            out = {"screenshot": name, "title": (page.title() or "")[:200], "final_url": page.url}
            page.screenshot(path=str(path), full_page=True)
        except Exception as e:
            browser.close()
            return {"error": f"screenshot failed: {e}"}
        browser.close()
    return out


def browser_recon(target: str, cookie: str = "") -> dict:
    """Real-browser recon for JS/CDN-fronted targets (Vercel, Cloudflare, SPAs). Headless Chromium
    renders the page and lets a same-origin JS challenge (e.g. Vercel's Security Checkpoint) solve
    itself, then extracts the ACTUAL surface that HTTP-only tools can't see: final status/title/url,
    server + security headers, links/scripts/forms (the real routes), the hosts the app talks to
    (in-scope vs blocked out-of-scope), cookies (incl. any challenge-clearance cookie), and a
    screenshot. Every request stays scope-gated — out-of-scope hosts are blocked and REPORTED.

    cookie: optional raw Cookie header ("name=value; name2=value2") to send — e.g. the Vercel/
    Cloudflare clearance cookie you obtained by passing the challenge once in your own authorized
    browser. Managed bot challenges (Vercel Attack Challenge Mode, Cloudflare Turnstile) are built
    to refuse headless automation, so a supplied clearance cookie is how you recon past them."""
    import re
    import time

    _check_nav(target)
    try:
        sync_playwright = _sync_playwright()
    except ImportError:
        return {"error": "playwright not installed in sandbox"}
    from ..config import EVIDENCE_DIR

    shots = EVIDENCE_DIR / "shots"
    shots.mkdir(parents=True, exist_ok=True)
    thost = (urlparse(target if "://" in target else f"//{target}").hostname or "shot").lower()
    name = f"{re.sub(r'[^A-Za-z0-9._-]', '_', thost)}-recon-{int(time.time())}.png"
    path = shots / name

    seen_hosts: set = set()
    blocked_hosts: set = set()
    main = {"status": None, "headers": {}}

    def _scope_route(route):
        url = route.request.url
        scheme = urlparse(url).scheme.lower()
        host = (urlparse(url).hostname or "").lower()
        if scheme in ("http", "https"):
            try:
                check(url)
            except OutOfScope:
                if host:
                    blocked_hosts.add(host)
                return route.abort()
            if host:
                seen_hosts.add(host)
            return route.continue_()
        if scheme in ("data", "blob", "about"):
            return route.continue_()
        return route.abort()

    mode = "headless"
    if not os.environ.get("DISPLAY"):
        # A HEADFUL browser under a virtual display (Xvfb, bundled in the Playwright image) presents
        # like a real browser and clears JS bot challenges (e.g. Vercel Attack Challenge Mode) that
        # flag headless Chromium. Start the display once; later calls reuse it.
        import subprocess
        try:
            subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1920x1080x24", "-nolisten", "tcp"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.environ["DISPLAY"] = ":99"
            time.sleep(1.5)
        except Exception:
            pass
    want_headful = bool(os.environ.get("DISPLAY"))

    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=not want_headful, args=_CHROMIUM_ARGS)
            mode = "headful" if want_headful else "headless"
        except Exception:
            browser = pw.chromium.launch(headless=True, args=_CHROMIUM_ARGS)
            mode = "headless"
        try:
            context = browser.new_context(**_context_opts(browser))
            if cookie:  # operator-supplied clearance cookie(s) from a passed challenge
                cks = []
                for part in cookie.split(";"):
                    if "=" in part:
                        n, v = part.strip().split("=", 1)
                        if n.strip():
                            cks.append({"name": n.strip(), "value": v.strip(), "url": target})
                if cks:
                    try:
                        context.add_cookies(cks)
                    except Exception:
                        pass
            context.route("**/*", _scope_route)
            context.add_init_script(_ws_guard_js(""))
            page = context.new_page()
            page.add_init_script(stealth.STEALTH_INIT_JS)

            def _on_response(resp):
                try:
                    if resp.request.is_navigation_request() and resp.request.frame == page.main_frame:
                        main["status"] = resp.status
                        main["headers"] = {k.lower(): v for k, v in resp.headers.items()}
                except Exception:
                    pass
            page.on("response", _on_response)

            page.goto(target, timeout=HTTP_TIMEOUT * 1000, wait_until="domcontentloaded")
            # Give a JS challenge time to solve and navigate to the real content. One reload
            # part-way helps a same-origin JS-only challenge that gates on a second visit.
            _marks = ("security checkpoint", "just a moment", "attention required", "checking your browser")
            deadline = time.time() + 35
            challenged = False
            reloaded = False
            while time.time() < deadline:
                t = (page.title() or "").lower()
                if any(m in t for m in _marks):
                    challenged = True
                    if not reloaded and time.time() > deadline - 20:
                        reloaded = True
                        try:
                            page.reload(timeout=HTTP_TIMEOUT * 1000, wait_until="domcontentloaded")
                        except Exception:
                            pass
                    page.wait_for_timeout(1500)
                    continue
                break
            page.wait_for_timeout(1200)

            data = page.evaluate(
                "() => {"
                "  const abs = u => { try { return new URL(u, location.href).href } catch(e){ return null } };"
                "  const uniq = a => [...new Set(a.filter(Boolean))];"
                "  const links = uniq([...document.querySelectorAll('a[href]')].map(a=>abs(a.getAttribute('href')))).slice(0,200);"
                "  const scripts = uniq([...document.querySelectorAll('script[src]')].map(s=>abs(s.getAttribute('src')))).slice(0,120);"
                "  const forms = [...document.querySelectorAll('form')].slice(0,40).map(f=>({"
                "    action: abs(f.getAttribute('action')||location.href),"
                "    method: (f.getAttribute('method')||'GET').toUpperCase(),"
                "    inputs: [...f.querySelectorAll('input,select,textarea')].map(i=>i.getAttribute('name')).filter(Boolean)}));"
                "  const gen = (document.querySelector('meta[name=generator]')||{}).content||'';"
                "  return {title: document.title, links, scripts, forms, generator: gen, html_len: document.documentElement.outerHTML.length};"
                "}"
            )
            cookies = [{"name": c.get("name"), "domain": c.get("domain")} for c in context.cookies()]
            page.screenshot(path=str(path), full_page=True)
            final_url = page.url
            final_title = (page.title() or "")[:200]
        except Exception as e:
            browser.close()
            return {"error": f"browser_recon failed: {e}"}
        browser.close()

    low_title = final_title.lower()
    still_blocked = any(m in low_title for m in ("security checkpoint", "just a moment", "attention required"))
    sec_keys = ["server", "x-powered-by", "x-vercel-id", "x-vercel-cache", "content-security-policy",
                "strict-transport-security", "x-frame-options", "x-content-type-options",
                "referrer-policy", "permissions-policy", "set-cookie"]
    sec_headers = {k: main["headers"][k] for k in sec_keys if k in main["headers"]}
    ext_hosts = sorted(h for h in seen_hosts if h and h != thost)

    out = {
        "final_url": final_url,
        "status": main["status"],
        "title": final_title,
        "generator": data.get("generator", ""),
        "security_headers": sec_headers,
        "links": data.get("links", []),
        "scripts": data.get("scripts", []),
        "forms": data.get("forms", []),
        "cookies": cookies,
        "talks_to": ext_hosts,
        "blocked_out_of_scope": sorted(blocked_hosts),
        "screenshot": name,
        "html_len": data.get("html_len"),
        "challenged": challenged,
        "mode": mode,
    }
    if still_blocked:
        out["verdict"] = "challenge-not-cleared"
        out["note"] = ("A bot/WAF challenge did not clear with same-origin assets only. The hosts in "
                       "blocked_out_of_scope were refused by the scope guard — if the challenge needs "
                       "one of them, add it to scope (or allow it) and re-run.")
    else:
        out["verdict"] = "rendered"
    return out
