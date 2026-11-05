"""Active authentication testing. Covers Shannon ✅ ATHN-01/02/03 + IDNT-04:
credentials-over-cleartext, default credentials, weak/absent lockout, account
enumeration. This SUBMITS real login attempts to the authorized target — scope-gated.
"""
import uuid

import httpx

from .. import safehttp, stealth
from ..config import HTTP_TIMEOUT
from ..scope_guard import check

_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"), ("admin", "changeme"),
    ("admin", "123456"), ("admin", ""), ("administrator", "password"), ("root", "root"),
    ("root", "toor"), ("test", "test"), ("user", "user"), ("guest", "guest"),
]
_ERR_KW = ("invalid", "incorrect", "failed", "wrong", "denied", "try again", "bad credentials")


def _login(client, target, uf, pf, u, p, extra):
    data = {uf: u, pf: p}
    if extra:
        data.update(extra)
    stealth.jitter()
    return client.post(target, data=data, headers=stealth.headers())


def _looks_success(r, baseline) -> bool:
    if 300 <= r.status_code < 400 and not (300 <= baseline.status_code < 400):
        return True
    if r.headers.get_list("set-cookie") and not baseline.headers.get_list("set-cookie"):
        return True
    base_has = any(k in baseline.text.lower() for k in _ERR_KW)
    this_has = any(k in r.text.lower() for k in _ERR_KW)
    return bool(base_has and not this_has and r.status_code < 400)


def auth(target: str, username_field: str = "username", password_field: str = "password",
              extra_fields: dict | None = None, default_creds: bool = True,
              test_lockout: bool = False, lockout_attempts: int = 8) -> dict:
    """POST login attempts to `target`. Checks: cleartext transport, account enumeration,
    default credentials, and (opt-in) weak lockout. extra_fields merges extra form fields."""
    check(target)
    out = {"target": target, "issues": []}
    if not target.lower().startswith("https"):
        out["issues"].append({"type": "transport", "note": "login over HTTP — credentials in cleartext (ATHN-01)"})

    with safehttp.client(target, timeout=HTTP_TIMEOUT, follow_redirects=False) as c:
        bogus_pw = "wrong_" + uuid.uuid4().hex[:8]
        try:
            baseline = _login(c, target, username_field, password_field,
                              "nouser_" + uuid.uuid4().hex[:8], bogus_pw, extra_fields)
        except httpx.HTTPError as e:
            return {"target": target, "error": f"login endpoint error: {e}"}

        # account enumeration: does a likely-real user respond differently to a bad password?
        try:
            admin_r = _login(c, target, username_field, password_field, "admin", bogus_pw, extra_fields)
            if admin_r.status_code != baseline.status_code or abs(len(admin_r.text) - len(baseline.text)) > 40:
                out["issues"].append({"type": "account-enumeration",
                                      "note": "'admin' vs random user give different responses (IDNT-04)",
                                      "admin_status": admin_r.status_code, "random_status": baseline.status_code})
        except httpx.HTTPError:
            pass

        # default credentials
        if default_creds:
            hits = []
            for u, p in _DEFAULT_CREDS:
                try:
                    r = _login(c, target, username_field, password_field, u, p, extra_fields)
                except httpx.HTTPError:
                    continue
                if _looks_success(r, baseline):
                    hits.append({"username": u, "password": p, "status": r.status_code})
            if hits:
                out["issues"].append({"type": "default-credentials", "note": "login appears to succeed (ATHN-02)",
                                      "credentials": hits})

        # weak lockout (opt-in, bounded)
        if test_lockout:
            locked = False
            for i in range(max(2, min(lockout_attempts, 15))):
                try:
                    r = _login(c, target, username_field, password_field, "admin", bogus_pw, extra_fields)
                except httpx.HTTPError:
                    break
                if any(k in r.text.lower() for k in ("locked", "too many", "rate limit", "temporarily disabled")):
                    locked = True
                    break
            if not locked:
                out["issues"].append({"type": "weak-lockout",
                                      "note": f"no lockout after {lockout_attempts} failed logins (ATHN-03)"})

    out["verdict"] = "VULNERABLE" if any(i["type"] in ("default-credentials",) for i in out["issues"]) \
        else ("review" if out["issues"] else "ok")
    return out
