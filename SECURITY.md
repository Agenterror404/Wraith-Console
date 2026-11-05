# Security policy

## Authorized use
Wraith is an offensive-security tool. Use it only against systems you own or are
explicitly authorized in writing to test. Unauthorized access to computer systems is
illegal in most jurisdictions. The default-deny scope guard (`scope.yaml`) refuses any
target not listed — do not disable it.

## Reporting a vulnerability
If you find a security issue in Wraith itself, please report it privately via this
repository's **Security** tab (open a private security advisory) rather than opening a
public issue.

## Hardening
- Run only on a trusted/private network (VPN, loopback) or behind TLS. It is a
  single-operator console, not a public service.
- Set a strong `WRAITH_UI_PASSWORD` and a random `WRAITH_UI_SECRET`.
- Leave `WRAITH_UI_INSECURE_COOKIE` unset unless you are on plain-HTTP loopback/VPN.
