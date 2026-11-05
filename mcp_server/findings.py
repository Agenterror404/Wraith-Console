"""Evidence store. Enforces 'no PoC, no finding' and exports a markdown report."""
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import EVIDENCE_DIR

# Ordered low→high: membership checks still work, and index() gives a DETERMINISTIC severity
# rank (a set has no stable order, so sorting by list(set).index was arbitrary).
SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    title: str
    severity: str
    target: str
    vuln_class: str          # e.g. sqli, xss, authz, idor
    description: str
    proof: str               # request/response or steps that CONFIRM it — required
    remediation: str = ""
    id: str = ""
    ts: float = field(default_factory=time.time)


def _store() -> Path:
    return EVIDENCE_DIR / "findings.jsonl"


def record(f: Finding) -> str:
    if f.severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(SEVERITIES)}")
    if not f.proof.strip():
        raise ValueError("no PoC, no finding — 'proof' is required")
    f.id = f.id or f"F-{int(f.ts)}-{hashlib.sha1(f.title.encode()).hexdigest()[:6]}"
    with open(_store(), "a") as fh:
        fh.write(json.dumps(asdict(f)) + "\n")
    return f.id


def load_all() -> list[dict]:
    p = _store()
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def _results_store() -> Path:
    return EVIDENCE_DIR / "results.jsonl"


def record_result(tool: str, target: str, kind: str, result) -> None:
    """Append a raw tool-run result (single tool, scan step, or phase-group step) so every run
    is exportable — not just manually-recorded findings. Best-effort: never raises into the
    request path. `kind` is 'tool' | 'scan' | 'bulk'."""
    try:
        if isinstance(result, dict):
            rc = result.get("returncode")
            err = result.get("error") or (result.get("reason") if result.get("refused") else None)
            body = result.get("stdout")
            if body is None:
                body = json.dumps(result, default=str)
        else:
            rc, err, body = None, None, str(result)
        row = {"ts": time.time(), "tool": tool, "target": target, "kind": kind,
               "rc": rc, "error": err, "output": (body or "")[:20000]}
        with open(_results_store(), "a") as fh:
            fh.write(json.dumps(row) + "\n")
    except Exception:
        pass  # evidence capture is best-effort; never break a tool run on it


def load_results() -> list[dict]:
    p = _results_store()
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def clear_results() -> int:
    """Clear the live captured-results store so the next export is a clean slate. Archives the
    current file to results-<ts>.bak on the same volume rather than destroying it (evidence is
    kept, just moved out of the live store). Returns how many rows were archived."""
    p = _results_store()
    if not p.exists():
        return 0
    n = sum(1 for line in p.read_text().splitlines() if line.strip())
    import datetime
    bak = p.with_name(f"results-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.bak")
    p.rename(bak)
    return n


def results_to_markdown(rows: list[dict]) -> str:
    import datetime
    out = ["# Scan Results", "", f"**Runs:** {len(rows)}", ""]
    for r in rows:
        ts = datetime.datetime.fromtimestamp(r.get("ts", 0)).strftime("%Y-%m-%d %H:%M:%S")
        meta = f"- when: {ts}  ·  kind: {r.get('kind', '')}  ·  rc: {r.get('rc')}"
        if r.get("error"):
            meta += f"  ·  note: {r['error']}"
        out += [f"## {r.get('tool', '?')} — {r.get('target', '')}", meta, "",
                "```", (r.get("output", "") or "").strip()[:8000], "```", ""]
    return "\n".join(out)


def export_markdown(target: str = "") -> str:
    rows = sorted(load_all(), key=lambda r: list(SEVERITIES).index(r["severity"]), reverse=True)
    out = ["# Pentest Report", ""]
    if target:
        out += [f"**Target:** {target}", ""]
    out += [f"**Findings:** {len(rows)}", ""]
    for r in rows:
        out += [
            f"## [{r['severity'].upper()}] {r['title']}",
            f"- **Class:** {r['vuln_class']}",
            f"- **Target:** {r['target']}",
            "",
            r["description"],
            "",
            "**Proof of concept:**",
            "```",
            r["proof"].strip(),
            "```",
        ]
        if r.get("remediation"):
            out += ["", f"**Remediation:** {r['remediation']}"]
        out += [""]
    return "\n".join(out)


def export_report_markdown(target: str = "") -> str:
    """Full report: curated findings first, then every captured tool run so a report has data
    even when no findings were hand-recorded (e.g. after a recon/vuln sweep)."""
    rows = load_results()
    if target:
        rows = [r for r in rows if target in (r.get("target", "") or "")]
    return export_markdown(target) + "\n\n---\n\n" + results_to_markdown(rows)


if __name__ == "__main__":
    # ponytail: self-check. No-proof finding must be rejected.
    import os, tempfile
    EVIDENCE_DIR_OVERRIDE = tempfile.mkdtemp()
    globals()["EVIDENCE_DIR"] = Path(EVIDENCE_DIR_OVERRIDE)
    try:
        record(Finding("x", "high", "t", "sqli", "d", proof=""))
        raise SystemExit("FAIL: empty proof should raise")
    except ValueError:
        pass
    fid = record(Finding("SQLi in login", "high", "http://juice-shop:3000", "sqli", "desc", proof="payload->response"))
    assert fid and load_all()[-1]["id"] == fid
    assert "SQLi in login" in export_markdown("http://juice-shop:3000")
    # I-4: id suffix is a stable content hash (same title -> same suffix)
    fid2 = record(Finding("SQLi in login", "low", "t", "sqli", "d", proof="p"))
    assert fid.split("-")[-1] == fid2.split("-")[-1]
    print("findings self-check OK")
