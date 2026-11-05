"""Scope-enforcing aggregation layer — the single choke point every tool call
passes through before reaching an upstream (local sandboxed tools, or an
external web-recon upstream that can reach the public internet).

Hardened per security review (C1): scope is enforced by VALUE SHAPE, not by
argument name. Every string anywhere in the args that looks like a destination
(a URL, an IP[:port], or a host.tld[:port]) is scope-checked; the call is
refused if any fails or if anything errors (fail closed). A name allowlist is
kept only as an extra "target-bearing tools must present a target" assertion.
Forwarding uses structured MCP args — no shell, no interpolation.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .scope_guard import OutOfScope, check

# Names that are KNOWN to carry a target. Used only to require that a
# target-bearing tool presents at least one — never as the thing that decides
# what gets scope-checked (that is done by value shape below).
TARGET_KEYS = {
    "target", "targets", "url", "urls", "uri", "uris", "host", "hosts",
    "hostname", "domain", "domains", "address", "base_url", "base", "origin",
    "origins", "endpoint", "endpoints", "site", "sites", "seed", "seeds",
    "allowed_domains", "scope", "extra_hosts",
}

_HOST_TLD = re.compile(r"(?=.*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
                       r"(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?::\d{1,5})?$")


def _is_targetish(s: str) -> bool:
    """True if the string looks like a network destination that must be scoped.
    Deliberately conservative to avoid flagging prose/payloads/version numbers,
    but it catches URLs, IPv4[:port], IPv6 (bare or bracketed), and host.tld[:port]."""
    if not isinstance(s, str) or not s or len(s) > 2048:
        return False
    if "://" in s:
        return True
    if s.startswith("["):                 # [ipv6] or [ipv6]:port
        cand = s[1:].split("]", 1)[0]
    elif s.count(":") >= 2:               # bare IPv6 literal
        cand = s
    else:                                 # host or host:port
        cand = s.split(":", 1)[0]
    try:
        ipaddress.ip_address(cand)        # IPv4 / IPv6 literal
        return True
    except ValueError:
        pass
    return bool(_HOST_TLD.match(s))


# Tools that make NO network call — recording/reporting only. They are exempt from the
# value-shape scope walk so a legitimate finding whose proof quotes an out-of-scope host
# isn't refused. (They still can't reach the network, so there is nothing to gate.)
NON_NETWORK = {"record_finding", "export_report", "show_scope"}


def _walk_strings(obj: Any):
    """Yield every string in a nested args structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _walk_strings(v)


def _named_target_values(args: dict) -> list[str]:
    out: list[str] = []
    for k, v in (args or {}).items():
        if k.lower() in TARGET_KEYS:
            out.extend(x for x in _walk_strings(v))
    return out


@dataclass
class Upstream:
    name: str
    tools: set[str]
    call: Callable[[str, dict], Awaitable[Any]]


class ScopeAggregator:
    def __init__(self, upstreams: list[Upstream], target_bearing: set[str]):
        self._upstreams = upstreams
        self._target_bearing = {t.lower() for t in target_bearing}
        self._route: dict[str, Upstream] = {}
        for up in upstreams:
            for t in up.tools:
                self._route[t] = up

    def tools(self) -> list[str]:
        return sorted(self._route)

    def _refuse(self, tool: str, args: dict) -> str | None:
        """Return a refusal reason if the call must not be forwarded, else None.
        Fail closed: ANY error while deciding is a refusal."""
        if tool.lower() in NON_NETWORK:
            return None  # recording/reporting tools make no network call
        try:
            named = _named_target_values(args)
            # everything that looks like a destination, anywhere in the args
            shaped = [s for s in _walk_strings(args) if _is_targetish(s)]
            to_check = list(dict.fromkeys(named + shaped))  # dedupe, keep order

            if tool.lower() in self._target_bearing and not named:
                return (f"'{tool}' is target-bearing but no recognized target argument "
                        f"was supplied — failing closed")
            for val in to_check:
                check(val)  # raises OutOfScope if not allowed
            return None
        except OutOfScope as e:
            return str(e)
        except Exception as e:  # never fail open on an unexpected shape/error
            return f"scope check errored, refusing: {e!r}"

    async def call(self, tool: str, args: dict | None = None) -> Any:
        args = args or {}
        up = self._route.get(tool)
        if up is None:
            return {"refused": True, "reason": f"unknown tool '{tool}'"}
        reason = self._refuse(tool, args)
        if reason is not None:
            return {"refused": True, "reason": reason}
        return await up.call(tool, args)


if __name__ == "__main__":
    import asyncio
    import os
    import tempfile

    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    f.write("targets:\n  - host: 172.28.0.2\n    port: 3000\n")
    f.close()
    os.environ["PENTEST_SCOPE_FILE"] = f.name

    seen = []

    async def fake_call(tool, args):
        seen.append((tool, args))
        return {"ok": True, "tool": tool}

    up = Upstream(name="fake",
                  tools={"recon_http", "crawl_site", "no_target_tool", "export_report"}, call=fake_call)
    agg = ScopeAggregator([up], target_bearing={"recon_http", "crawl_site"})

    async def main():
        T = "http://172.28.0.2:3000"
        assert (await agg.call("recon_http", {"target": T})).get("ok")
        # C1: destination hidden under a non-recognized / list key must be caught
        before = len(seen)
        r = await agg.call("crawl_site", {"url": T, "allowed_domains": ["evil.com"]})
        assert r.get("refused") and len(seen) == before, r
        r = await agg.call("crawl_site", {"url": T, "seeds": ["http://evil.com"]})
        assert r.get("refused"), r
        # C1: a URL buried in an arbitrary nested arg is still checked
        r = await agg.call("crawl_site", {"url": T, "opts": {"notify": "http://evil.com/x"}})
        assert r.get("refused"), r
        # C2: backslash host refused
        r = await agg.call("recon_http", {"target": "http://evil.com\\@172.28.0.2:3000"})
        assert r.get("refused"), r
        # H2: port-less target refused against :3000 entry
        r = await agg.call("recon_http", {"target": "http://172.28.0.2"})
        assert r.get("refused"), r
        # target-bearing with no recognized target => fail closed
        r = await agg.call("recon_http", {"method": "GET"})
        assert r.get("refused"), r
        # benign non-target args pass (no false positive on version-ish strings)
        r = await agg.call("recon_http", {"target": T, "note": "payload 1.2.3 ' OR 1=1--"})
        assert r.get("ok"), r
        # unknown tool refused
        assert (await agg.call("ghost", {})).get("refused")
        # M-2: IPv6 (bare + bracketed) is detected as targetish; versions/prose are not
        assert _is_targetish("2001:db8::1") and _is_targetish("[::1]:8080")
        assert not _is_targetish("1.2.3") and not _is_targetish("just some text")
        # L-2: non-network tools are exempt — a finding quoting an out-of-scope host records
        r = await agg.call("export_report", {"target": T, "proof": "redirects to http://evil.com"})
        assert r.get("ok"), r
        print("aggregate scope-gate self-check OK")

    asyncio.run(main())
