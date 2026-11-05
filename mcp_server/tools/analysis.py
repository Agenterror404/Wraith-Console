"""Analysis tools. http_request is the workhorse; the rest wrap standard binaries
or run simple, deterministic detection heuristics. All scope-gated.

These confirm vuln *classes* against an authorized, sandboxed target — they are
detection wrappers, not an exploit catalog. Payload specifics live in the
external tools (sqlmap) or are supplied per-call by the driver model.
"""
import os
import uuid

import httpx

from .. import safehttp, stealth
from ..config import HTTP_TIMEOUT
from ..scope_guard import check

# Tools that wrap an external binary run in the sealed tool-runner container (scratch-only
# FS, egress only via the scope-proxy). The Console/MCP dispatch a job to it over the
# internal network rather than shelling out in-process.
TOOL_RUNNER = os.environ.get("TOOL_RUNNER", "http://wraith-tool-runner:9000")


def http_request(
    target: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    cookies: dict | None = None,
) -> dict:
    """Arbitrary authenticated HTTP request to an in-scope target. The core primitive."""
    check(target)
    stealth.jitter()
    r = safehttp.request(
        method.upper(),
        target,
        headers=stealth.headers(headers),  # browser-like defaults; caller headers win
        content=body,
        cookies=cookies or {},
        timeout=HTTP_TIMEOUT,
        follow_redirects=False,
    )
    return {
        "status": r.status_code,
        "headers": dict(r.headers),
        "body": r.text[:20000],
        "len": len(r.content),
    }


# sqlmap flags that would retarget it off the authorized host or escalate to OS/file
# access. extra_args is screened against these before sqlmap runs.
_DENIED_SQLMAP = (
    "-u", "--url", "-r", "-l", "-m", "-g", "-c", "-d", "--data",
    "--os-shell", "--os-pwn", "--os-cmd", "--os-smbrelay", "--sql-shell", "--sql-query",
    "--eval", "--file-read", "--file-write", "--file-dest", "--crawl", "--proxy", "--tor",
    # code-execution-via-script flags (load/run arbitrary Python or shell on findings):
    "--tamper", "--preprocess", "--postprocess", "--alert",
)


def injection(target: str, extra_args: list[str] | None = None) -> dict:
    """Run sqlmap against an in-scope URL via the sealed sqlmap-runner container.
    sqlmap no longer runs in this process: the runner confines its filesystem to a
    scratch dir and forces all its traffic through the scope-proxy. extra_args is
    screened here too (defense in depth) before dispatch."""
    check(target)
    extra = [str(a) for a in (extra_args or [])]
    for a in extra:
        la = a.lower()
        if any(la == d or la.startswith(d + "=") for d in _DENIED_SQLMAP):
            return {"refused": True, "reason": f"extra_arg {a!r} is a disallowed sqlmap flag"}
        if "://" in la:
            return {"refused": True, "reason": f"extra_arg {a!r} looks like a URL/target"}
    try:
        r = httpx.post(f"{TOOL_RUNNER}/run", json={"tool": "sqlmap", "target": target, "args": extra}, timeout=660)
    except httpx.HTTPError as e:
        return {"error": f"tool-runner unreachable ({e}); is the sandbox container up?"}
    if r.status_code != 200:
        return {"error": f"tool-runner returned {r.status_code}", "detail": r.text[:2000]}
    try:
        return r.json()
    except ValueError:
        return {"error": "sqlmap-runner returned non-JSON", "detail": r.text[:2000]}


def xss(target: str, param: str, method: str = "GET") -> dict:
    """Reflection check: send a unique marker in `param`, report if it returns unescaped.
    Confirms reflection only — not a stored/DOM verdict (use browser_scenario for those)."""
    check(target)
    marker = f"xss{uuid.uuid4().hex[:8]}zzq"
    probe = f"<{marker}>"
    stealth.jitter()
    if method.upper() == "GET":
        r = safehttp.get(target, params={param: probe}, timeout=HTTP_TIMEOUT,
                      follow_redirects=False, headers=stealth.headers())
    else:
        r = safehttp.request(method.upper(), target, data={param: probe},
                          timeout=HTTP_TIMEOUT, follow_redirects=False, headers=stealth.headers())
    reflected_raw = probe in r.text
    reflected_encoded = f"&lt;{marker}&gt;" in r.text
    return {
        "param": param,
        "reflected_unescaped": reflected_raw,
        "reflected_encoded": reflected_encoded,
        "verdict": "candidate" if reflected_raw else ("escaped" if reflected_encoded else "no-reflection"),
    }


def authz(target: str, session_a: dict, session_b: dict) -> dict:
    """Session diffing: fetch `target` with two cookie sets, compare. Detects missing
    access control (e.g. B sees A's resource). Returns both responses for the model to judge."""
    check(target)
    out = {}
    for name, cookies in (("a", session_a), ("b", session_b)):
        stealth.jitter()
        r = safehttp.get(target, cookies=cookies or {}, timeout=HTTP_TIMEOUT,
                      follow_redirects=False, headers=stealth.headers())
        out[name] = {"status": r.status_code, "len": len(r.content), "body": r.text[:8000]}
    out["same_status"] = out["a"]["status"] == out["b"]["status"]
    out["same_len"] = out["a"]["len"] == out["b"]["len"]
    return out
