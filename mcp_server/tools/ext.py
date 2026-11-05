"""External-binary tools dispatched to the sealed tool-runner container.

Each wrapper POSTs {tool,target,args} to the runner (which confines the filesystem and
forces egress through the scope-proxy) and returns its JSON. The target is scope-checked
here too (fast refuse + the MCP path has no Console gate); the runner re-checks and the
proxy enforces scope per request. These are thin — richer output parsing can come later.
"""
import contextvars
import json
import os

import httpx

from ..scope_guard import check

TOOL_RUNNER = os.environ.get("TOOL_RUNNER", "http://wraith-tool-runner:9000")

# Live-output sink: when the caller binds one (the Console does, per tool run), run() streams
# the runner's output and feeds each line to sink(tool, line) as it arrives. Ambient via a
# ContextVar so none of the 24 wrappers need a callback param — the Console copies the context
# with the sink set into the executor thread that runs the tool. Unset (MCP path) => blocking.
_LINE_SINK: contextvars.ContextVar = contextvars.ContextVar("wraith_line_sink", default=None)
# Stop signal: a no-arg callable returning True when the user hit STOP. Bound by the Console
# alongside the sink. When it flips True mid-stream we break, which closes the HTTP stream and
# triggers the runner's client-disconnect kill — so an in-flight tool dies promptly instead of
# running to its full timeout (responsive STOP, not just between-steps).
_STOP_CHECK: contextvars.ContextVar = contextvars.ContextVar("wraith_stop_check", default=None)


def run(tool: str, target: str, args: list[str] | None = None, timeout: float = 200.0,
        scoped: bool = True) -> dict:
    if scoped:
        check(target)
    payload = {"tool": tool, "target": target, "args": list(args or [])}
    sink = _LINE_SINK.get()
    if sink is None:
        try:
            r = httpx.post(f"{TOOL_RUNNER}/run", json=payload, timeout=timeout)
        except httpx.HTTPError as e:
            return {"error": f"tool-runner unreachable ({e}); is the sandbox container up?"}
        if r.status_code != 200:
            return {"error": f"tool-runner returned {r.status_code}", "detail": r.text[:2000]}
        try:
            return r.json()
        except ValueError:
            return {"error": "tool-runner returned non-JSON", "detail": r.text[:2000]}
    # streaming: feed each output line to the sink; the final non-line object is the result
    payload["stream"] = True
    stop = _STOP_CHECK.get()
    result = {"error": "tool-runner produced no result"}
    stopped = False
    try:
        with httpx.stream("POST", f"{TOOL_RUNNER}/run", json=payload, timeout=timeout) as r:
            if r.status_code != 200:
                return {"error": f"tool-runner returned {r.status_code}"}
            for raw in r.iter_lines():
                if stop is not None and stop():
                    stopped = True
                    break  # STOP: leaving the context closes the stream -> runner kills the tool
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except ValueError:
                    continue
                if "line" in obj:
                    try:
                        sink(tool, obj["line"])
                    except Exception:
                        pass  # a logging hiccup must never kill the tool stream
                else:
                    result = obj
    except httpx.HTTPError as e:
        return {"error": f"tool-runner stream failed ({e}); is the sandbox container up?"}
    if stopped:
        return {"stopped": True, "tool": tool, "note": "stopped by user"}
    return result


def whatweb(target: str) -> dict:
    """Fingerprint the target's web stack (server, framework, CMS) with whatweb."""
    return run("whatweb", target, timeout=90)


def wafw00f(target: str) -> dict:
    """Detect a WAF/CDN in front of the target with wafw00f."""
    return run("wafw00f", target, timeout=90)


def arjun(target: str) -> dict:
    """Discover hidden HTTP parameters on the target with arjun."""
    return run("arjun", target, timeout=260)


def katana(target: str) -> dict:
    """Crawl the target and list discovered endpoints/URLs with katana."""
    return run("katana", target, timeout=200)


def ffuf(target: str) -> dict:
    """Content/directory discovery on the target with ffuf (bundled common wordlist)."""
    return run("ffuf", target, timeout=260)


# --- scanners ---
def nuclei(target: str) -> dict:
    """Template-based vulnerability scan with nuclei (baked-in offline templates)."""
    return run("nuclei", target, timeout=620)


def nikto(target: str) -> dict:
    """Web-server misconfiguration / known-vuln scan with nikto."""
    return run("nikto", target, timeout=260)


def wapiti(target: str) -> dict:
    """Black-box web-application vulnerability scan with wapiti."""
    return run("wapiti", target, timeout=620)


# --- injection / exploitation ---
def commix(target: str) -> dict:
    """Automated command-injection exploitation with commix."""
    return run("commix", target, timeout=320)


def sstimap(target: str) -> dict:
    """Server-side template injection detection/exploitation with SSTImap."""
    return run("sstimap", target, timeout=260)


def dalfox(target: str) -> dict:
    """XSS discovery and verification with dalfox."""
    return run("dalfox", target, timeout=320)


def crlfuzz(target: str) -> dict:
    """CRLF-injection testing with crlfuzz."""
    return run("crlfuzz", target, timeout=200)


def corsy(target: str) -> dict:
    """CORS misconfiguration testing with Corsy."""
    return run("corsy", target, timeout=140)


def oralyzer(target: str) -> dict:
    """Open-redirect testing with Oralyzer."""
    return run("oralyzer", target, timeout=140)


# --- session / api / crypto ---
def jwt_tool(jwt: str) -> dict:
    """Analyze/crack a supplied JWT with jwt_tool (offline — no network, not scoped)."""
    return run("jwt_tool", jwt, timeout=140, scoped=False)


def testssl(target: str) -> dict:
    """Full TLS/cipher/cert audit with testssl.sh (via the scope-proxy)."""
    return run("testssl", target, timeout=320)


def graphw00f(target: str) -> dict:
    """Fingerprint the GraphQL engine behind the target with graphw00f."""
    return run("graphw00f", target, timeout=140)


def clairvoyance(target: str) -> dict:
    """Recover a GraphQL schema via field suggestions (introspection off) with clairvoyance."""
    return run("clairvoyance", target, timeout=260)


def kiterunner(target: str) -> dict:
    """API route/endpoint discovery with kiterunner (bundled wordlist)."""
    return run("kiterunner", target, timeout=320)


def smuggler(target: str) -> dict:
    """HTTP request-smuggling detection with smuggler."""
    return run("smuggler", target, timeout=200)


# --- js / secrets ---
def linkfinder(target: str) -> dict:
    """Extract endpoints from the target's JavaScript with LinkFinder."""
    return run("linkfinder", target, timeout=140)


def secretfinder(target: str) -> dict:
    """Find API keys/secrets in the target's JavaScript with SecretFinder."""
    return run("secretfinder", target, timeout=140)


def cmseek(target: str) -> dict:
    """Detect and fingerprint the target's CMS with CMSeeK."""
    return run("cmseek", target, timeout=200)


# --- content discovery / CMS / advanced XSS ---
def feroxbuster(target: str) -> dict:
    """Recursive content/directory discovery with feroxbuster (depth 2, via the scope-proxy)."""
    return run("feroxbuster", target, timeout=320)


def wpscan(target: str) -> dict:
    """WordPress enumeration (vulnerable plugins + users) with wpscan, via the scope-proxy."""
    return run("wpscan", target, timeout=420)


def xsstrike(target: str) -> dict:
    """Context-aware reflected/DOM XSS fuzzing with XSStrike."""
    return run("xsstrike", target, timeout=320)


# --- Stage A gap-fill ---
def nosqli(target: str) -> dict:
    """NoSQL (MongoDB-style) injection scan of the target URL with nosqli."""
    return run("nosqli", target, timeout=320)


def ppfuzz(target: str) -> dict:
    """Prototype-pollution fuzzing of the target URL with ppfuzz."""
    return run("ppfuzz", target, timeout=200)


def joomscan(target: str) -> dict:
    """Joomla vulnerability/component enumeration with OWASP JoomScan."""
    return run("joomscan", target, timeout=420)


def droopescan(target: str) -> dict:
    """Drupal enumeration (modules, themes, version) with droopescan."""
    return run("droopescan", target, timeout=320)


def gobuster_vhost(target: str) -> dict:
    """Virtual-host discovery (hidden sites on the same server) with gobuster vhost."""
    return run("gobuster_vhost", target, timeout=260)


def nuclei_dast(target: str) -> dict:
    """Active-fuzzing vuln scan (injection/SSRF/redirect/XXE) with nuclei -dast."""
    return run("nuclei_dast", target, timeout=620)
