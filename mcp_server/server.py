"""FastMCP entrypoint. Registers every tool and exposes the scope guard as a refuse
boundary. Stdio transport only — the driver spawns it over docker exec / ssh; there
is no network listener to reach or protect.

  python -m mcp_server.server
"""
import functools
import inspect

from fastmcp import FastMCP

from . import findings
from .config import load_scope
from .scope_guard import OutOfScope
from .tools import analysis, api, authn, browser, ext, injection, misconfig, recon, session, webflaws

mcp = FastMCP("wraith")


def _guarded(fn):
    """Turn an OutOfScope into a structured refuse instead of a crash.
    Preserves fn's signature so FastMCP can parse the tool schema."""
    @functools.wraps(fn)
    def wrap(*a, **k):
        try:
            return fn(*a, **k)
        except OutOfScope as e:
            return {"refused": True, "reason": str(e)}
    wrap.__signature__ = inspect.signature(fn)  # hide the *args wrapper from the schema parser
    return wrap


# --- recon ---
mcp.tool()(_guarded(recon.recon_http))
mcp.tool()(_guarded(recon.enum_paths))
# --- analysis ---
mcp.tool()(_guarded(analysis.http_request))
mcp.tool()(_guarded(analysis.injection))
mcp.tool()(_guarded(analysis.xss))
mcp.tool()(_guarded(analysis.authz))
# --- browser ---
mcp.tool()(_guarded(browser.browser_scenario))
mcp.tool()(_guarded(browser.screenshot))
# --- misconfig / crypto (Shannon CONF, CRYP) ---
mcp.tool()(_guarded(misconfig.check_config))
mcp.tool()(_guarded(misconfig.tls))
# --- active injection (Shannon INPV-11/12/18, ATHZ-01) ---
mcp.tool()(_guarded(injection.cmdi))
mcp.tool()(_guarded(injection.ssti))
mcp.tool()(_guarded(injection.path_traversal))
# --- web flaws (Shannon INPV-19, CLNT-04, INPV-02) ---
mcp.tool()(_guarded(webflaws.open_redirect))
mcp.tool()(_guarded(webflaws.ssrf))
mcp.tool()(_guarded(webflaws.stored_xss))
# --- session / csrf (Shannon SESS) ---
mcp.tool()(_guarded(session.csrf))
mcp.tool()(_guarded(session.session))
# --- auth (Shannon ATHN, IDNT) ---
mcp.tool()(_guarded(authn.auth))
# --- api (Shannon APIT) ---
mcp.tool()(_guarded(api.api))
# --- recon pack (external binaries via the sealed tool-runner) ---
mcp.tool()(_guarded(ext.whatweb))
mcp.tool()(_guarded(ext.wafw00f))
mcp.tool()(_guarded(ext.arjun))
mcp.tool()(_guarded(ext.katana))
mcp.tool()(_guarded(ext.ffuf))
# --- scanners ---
mcp.tool()(_guarded(ext.nuclei))
mcp.tool()(_guarded(ext.nikto))
mcp.tool()(_guarded(ext.wapiti))
# --- injection / exploitation ---
mcp.tool()(_guarded(ext.commix))
mcp.tool()(_guarded(ext.sstimap))
mcp.tool()(_guarded(ext.dalfox))
mcp.tool()(_guarded(ext.crlfuzz))
mcp.tool()(_guarded(ext.corsy))
mcp.tool()(_guarded(ext.oralyzer))
# --- session / api / crypto ---
mcp.tool()(_guarded(ext.jwt_tool))
mcp.tool()(_guarded(ext.testssl))
mcp.tool()(_guarded(ext.graphw00f))
mcp.tool()(_guarded(ext.clairvoyance))
mcp.tool()(_guarded(ext.kiterunner))
mcp.tool()(_guarded(ext.smuggler))
# --- js / secrets ---
mcp.tool()(_guarded(ext.linkfinder))
mcp.tool()(_guarded(ext.secretfinder))
mcp.tool()(_guarded(ext.cmseek))

mcp.tool()(_guarded(ext.feroxbuster))
mcp.tool()(_guarded(ext.wpscan))
mcp.tool()(_guarded(ext.xsstrike))

mcp.tool()(_guarded(ext.nosqli))
mcp.tool()(_guarded(ext.ppfuzz))
mcp.tool()(_guarded(ext.joomscan))
mcp.tool()(_guarded(ext.droopescan))
mcp.tool()(_guarded(ext.gobuster_vhost))
mcp.tool()(_guarded(ext.nuclei_dast))


# --- evidence ---
@mcp.tool()
def record_finding(title: str, severity: str, target: str, vuln_class: str,
                   description: str, proof: str, remediation: str = "") -> dict:
    """Record a CONFIRMED finding. Rejected unless `proof` is non-empty (no PoC, no finding)."""
    try:
        fid = findings.record(findings.Finding(
            title=title, severity=severity, target=target, vuln_class=vuln_class,
            description=description, proof=proof, remediation=remediation))
        return {"id": fid, "recorded": True}
    except ValueError as e:
        return {"recorded": False, "reason": str(e)}


@mcp.tool()
def export_report(target: str = "") -> dict:
    """Export all recorded findings as a markdown report; returns the path and the text."""
    from .config import EVIDENCE_DIR
    md = findings.export_markdown(target)
    path = EVIDENCE_DIR / "report.md"
    path.write_text(md)
    return {"path": str(path), "markdown": md}


@mcp.tool()
def show_scope() -> dict:
    """Return the current scope allowlist so the driver can confirm what it may touch."""
    return load_scope()


if __name__ == "__main__":
    mcp.run()  # stdio only
