<div align="center">

# 👻 WRAITH CONSOLE

### GHOST IN YOUR STACK

A scope-locked, self-hosted web console for **authorized** web-application security testing.

</div>

---

## ⚠️ Authorized use only

Wraith is an offensive-security tool. Point it **only** at systems you own or have
explicit, written permission to test. Unauthorized access to computer systems is illegal
in most jurisdictions, and you are solely responsible for how you use this software.

Wraith is built to make misuse hard: it is **default-deny**. Every tool call is
scope-checked server-side before it runs, and anything not listed in `scope.yaml` is
refused and never dispatched.

---

## What it is

Wraith Console is a single-operator web UI that drives a catalog of well-known
open-source security tools (nuclei, sqlmap, ffuf, feroxbuster, dalfox, nikto, wpscan,
testssl, katana, and more) behind one consistent interface — with a hard scope boundary
in front of all of them.

- **Default-deny scope guard** — every target-shaped string, anywhere in a tool's
  arguments, is validated against `scope.yaml` *by value shape* (not by argument name)
  and fails closed. Out-of-scope → refused.
- **In-process execution** — the UI runs the tools in-process; the scope guard is the
  boundary, and each tool re-checks internally (belt and suspenders).
- **Phase scans** — Recon Sweep · Vuln Scan · Injection Suite · Config & Crypto ·
  Session & Identity · API & GraphQL · JS & Secrets.
- **Live streaming terminal**, a findings table with evidence, and Markdown report export.
- **Browser automation** via Playwright / a patched Chromium for JS-heavy targets.
- **Single shared-password login** with a signed, HttpOnly, SameSite=Strict session
  cookie; a per-session CSRF token plus an Origin/Referer same-origin check on every POST;
  a strict CSP (`script-src 'self'`, no inline JS, no third-party JS).

Built with FastAPI and server-rendered HTML fragments — no build step, no SPA.

## Quick start (Docker)

```bash
cp .env.example .env
# set WRAITH_UI_PASSWORD and WRAITH_UI_SECRET  (secret: openssl rand -base64 48)

docker build -t wraith-console .
docker run --rm -p 8000:8000 --env-file .env wraith-console
# open http://localhost:8000
```

> The image bakes in the external tool arsenal, so the first build pulls a lot and takes
> a while. Tools install tolerantly — one that fails to install simply reports
> "not installed" at runtime instead of breaking the image.

## Quick start (local, no Docker)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-ui.txt
playwright install chromium
export WRAITH_UI_PASSWORD='change-me' WRAITH_UI_SECRET="$(openssl rand -base64 48)"
export WRAITH_UI_INSECURE_COOKIE=1          # only if serving over plain HTTP on localhost
uvicorn ui.app:app --host 127.0.0.1 --port 8000
```

The UI and the browser/injection tools run without anything else installed. The other
scans shell out to external CLIs (nuclei, ffuf, nikto, …), which must be on your `PATH`
for those scans to work — the Docker image is the easy way to get the full set.

## Scope

Edit `scope.yaml`. Default-deny: anything not listed is refused.

```yaml
targets:
  - host: your-authorized-target.example.com
    port: 443
```

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `WRAITH_UI_PASSWORD` | yes | — | Login password (console won't start without it) |
| `WRAITH_UI_SECRET` | yes | — | Session-cookie signing secret (`openssl rand -base64 48`) |
| `WRAITH_UI_USERNAME` | no | `Agent` | Login username |
| `WRAITH_UI_INSECURE_COOKIE` | no | off | Allow the session cookie over plain HTTP — trusted/private networks only |
| `PENTEST_SCOPE_FILE` | no | `./scope.yaml` | Path to the scope file |
| `PENTEST_EVIDENCE_DIR` | no | `./evidence` | Where findings/evidence are written |
| `PENTEST_EXIT` | no | `chicago` | Browser fingerprint geo (timezone/locale/geolocation) to match your egress |

## Security model

- The scope guard is the single boundary; it validates by value shape and fails closed.
- Session cookie is signed (itsdangerous), HttpOnly, SameSite=Strict, with a TTL. Put it
  behind TLS to get `Secure` cookies back (recommended for anything but loopback).
- Per-session CSRF token + Origin/Referer same-origin check on every POST.
- Strict CSP, security headers, no stack traces to the client.
- Login is rate-limited; concurrent tool runs are bounded by a worker pool.

Serve Wraith only on a trusted/private network (VPN, loopback) or behind TLS. It is a
single-operator console, not a public service.

## Optional: MCP server mode

`mcp_server/` can also be run as a stdio MCP server (`python -m mcp_server.server`) to
drive the same scope-locked tools from an MCP client. That mode additionally requires
`fastmcp` (`pip install fastmcp==4.1.0`).

## License

MIT © 2026 Agenterror404 — see [LICENSE](LICENSE).
