"""Scope guard: every tool runs its target through check() before acting.

Default-deny allowlist (scope.yaml). Hardened against the bypasses found in the
security review:
  * illegal chars (backslash, whitespace, controls) are REJECTED, not parsed —
    closes the urlparse-vs-browser differential (http://evil.com\\@host).
  * effective port is enforced — a port-less target does NOT match a port-pinned
    entry (no sneaking onto :80/:443 when only :3000 was authorized).
  * any parse failure becomes OutOfScope, never a leaked ValueError.
Empty/missing scope => everything refused.
"""
import ipaddress
import socket
from urllib.parse import urlparse

from .config import load_scope

# illegal in a target: backslash, any whitespace, any C0 control char.
_BAD_CHARS = set("\\\t\n\r\x0b\x0c ") | {chr(c) for c in range(0x20)}
_DEFAULT_PORT = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}

# Resolutions into these ranges are refused even when the host string is in scope:
# loopback, link-local (incl. 169.254.169.254 cloud-metadata), and their IPv6 forms.
_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _ip_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # Canonicalize IPv4-mapped / NAT64 IPv6 to the embedded IPv4 before range checks, so
    # ::ffff:169.254.169.254 and NAT64 forms can't sneak past the v4 metadata/loopback nets.
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in _NAT64:
            ip = ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
    return any(ip in net for net in _BLOCKED_NETS)


def resolve_pin(host: str) -> str:
    """Resolve `host` to a single vetted IP for connection pinning. An IP literal passes
    through after the block check; a hostname resolves and returns the first non-blocked IP.
    Raises OutOfScope if it can't resolve or resolves only to blocked ranges. Callers pin the
    connection to this IP so a DNS rebind between check() and the real connect can't redirect
    the tool to loopback/metadata/internal."""
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        if _ip_blocked(h):
            raise OutOfScope(f"{host} is a blocked address (loopback/link-local/metadata)")
        return h
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError) as e:
        raise OutOfScope(f"cannot resolve {host}: {e}")
    for ai in infos:
        ip = ai[4][0]
        if not _ip_blocked(ip):
            return ip
    raise OutOfScope(f"{host} resolves only to blocked ranges — refused")


def host_blocked(host: str) -> bool:
    """True if host is, or resolves to, a loopback/link-local/metadata address.
    IP literals are checked directly; hostnames are resolved (resolution failure =>
    not blocked, the connection will just fail). Closes in-scope-name -> metadata SSRF.
    Residual: DNS can still rebind between this check and a tool's own connect."""
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return _ip_blocked(h)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return False
    return any(_ip_blocked(ai[4][0]) for ai in infos)


class OutOfScope(Exception):
    """Raised when a target is not on the allowlist. Tools surface this as a hard refuse."""


def _effective_port(scheme: str, port: int | None) -> int | None:
    if port is not None:
        return port
    return _DEFAULT_PORT.get((scheme or "http").lower())


def _entry_matches(host: str, eport: int | None, entry) -> bool:
    if isinstance(entry, str):
        ehost, _, ep = entry.partition(":")
        ehost = ehost.lower()
        eport_entry = int(ep) if ep else None
    else:
        ehost = str(entry.get("host", "")).lower()
        eport_entry = entry.get("port")
    if host != ehost:
        return False
    # entry pins a port => the target's effective port must equal it exactly.
    if eport_entry is not None and eport != eport_entry:
        return False
    return True


def check(target: str) -> str:
    """Validate a URL or host[:port]. Returns the target unchanged, or raises
    OutOfScope. Any malformed/suspicious input raises OutOfScope (fail closed)."""
    if not isinstance(target, str) or not target:
        raise OutOfScope(f"invalid target {target!r}")
    bad = [c for c in target if c in _BAD_CHARS]
    if bad:
        raise OutOfScope(f"target contains illegal char(s) {bad!r}: {target!r}")

    raw = target if "://" in target else f"//{target}"
    try:
        p = urlparse(raw, scheme="http")
        host = (p.hostname or "").lower()
        port = p.port  # may raise ValueError on a bad port
    except ValueError as e:
        raise OutOfScope(f"unparseable target {target!r}: {e}")
    if not host:
        raise OutOfScope(f"cannot parse host from {target!r}")

    eport = _effective_port(p.scheme, port)
    entries = load_scope().get("targets", [])
    if not entries:
        raise OutOfScope("scope.yaml has no targets — refusing everything (default-deny)")
    if any(_entry_matches(host, eport, e) for e in entries):
        if host_blocked(host):
            raise OutOfScope(
                f"{host} resolves to a blocked range (loopback/link-local/metadata) — refused")
        return target
    raise OutOfScope(f"{host}:{eport} is not in scope.yaml — refused")


if __name__ == "__main__":
    import os
    import tempfile

    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    f.write("targets:\n  - host: juice-shop\n    port: 3000\n")
    f.close()
    os.environ["PENTEST_SCOPE_FILE"] = f.name

    # in scope
    assert check("http://juice-shop:3000/rest") == "http://juice-shop:3000/rest"
    assert check("juice-shop:3000") == "juice-shop:3000"
    # out of scope host
    for bad in ("http://evil.com", "http://127.0.0.1:3000"):
        try:
            check(bad); raise SystemExit(f"FAIL: {bad} should refuse")
        except OutOfScope:
            pass
    # H2: port-less or wrong port must NOT match a port-pinned entry
    for bad in ("http://juice-shop", "http://juice-shop:80", "http://juice-shop:9999"):
        try:
            check(bad); raise SystemExit(f"FAIL(H2): {bad} should refuse")
        except OutOfScope:
            pass
    # C2: backslash / parser-differential must be rejected
    for bad in ("http://evil.com\\@juice-shop:3000", "http://juice-shop:3000\\x",
                "http://juice shop:3000", "http://juice-shop:3000\n"):
        try:
            check(bad); raise SystemExit(f"FAIL(C2): {bad!r} should refuse")
        except OutOfScope:
            pass
    # M1: malformed port => OutOfScope, not ValueError
    try:
        check("http://juice-shop:notaport"); raise SystemExit("FAIL(M1): should refuse")
    except OutOfScope:
        pass
    # empty scope => refuse all
    open(f.name, "w").write("targets: []\n")
    try:
        check("http://juice-shop:3000"); raise SystemExit("FAIL: empty scope should refuse")
    except OutOfScope:
        pass
    # SSRF guard: an in-scope loopback/metadata IP is still refused (resolution guard)
    open(f.name, "w").write("targets:\n  - host: 127.0.0.1\n  - host: 169.254.169.254\n")
    for bad in ("http://127.0.0.1/x", "http://169.254.169.254/latest/meta-data/"):
        try:
            check(bad); raise SystemExit(f"FAIL(SSRF): {bad} should refuse")
        except OutOfScope:
            pass
    print("scope_guard self-check OK")
