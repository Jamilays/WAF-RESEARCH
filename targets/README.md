# Vulnerable targets

Three deliberately vulnerable apps running behind Traefik + the WAF matrix. All are internal-only — never expose these services to the LAN, ever.

| Target | Image | Internal port | Auth | Language |
|---|---|---|---|---|
| DVWA | `vulnerables/web-dvwa:latest` | 80 | admin / password | PHP + MySQL |
| WebGoat | `webgoat/webgoat:v2025.3` | 8080 | self-register | Java (Spring) |
| Juice Shop | `bkimminich/juice-shop:v19.2.1` | 3000 | none required for most endpoints | Node |

## DVWA init

Runs once on first `docker compose up` via the one-shot `dvwa-init` container (see [`dvwa/init/init-dvwa.sh`](dvwa/init/init-dvwa.sh)): waits for DVWA, creates the MySQL schema, verifies admin login. Idempotent.

DVWA's security level (low/medium/high) is *not* set here — it's a PHP session variable, so the engine (Phase 3+) sets it per-session when it authenticates.

## Reaching a target

Via Traefik, using the Host header (no `/etc/hosts` edits needed):

```bash
# baseline (no WAF)
curl -H 'Host: baseline-dvwa.local'      http://127.0.0.1:8000/
curl -H 'Host: baseline-webgoat.local'   http://127.0.0.1:8000/WebGoat/
curl -H 'Host: baseline-juiceshop.local' http://127.0.0.1:8000/

# through a WAF
curl -H 'Host: modsec-dvwa.local'        http://127.0.0.1:8000/
curl -H 'Host: coraza-juiceshop.local'   http://127.0.0.1:8000/
curl -H 'Host: shadowd-webgoat.local'    http://127.0.0.1:8000/
```

## Safety

- All target ports are internal-only — only Traefik (127.0.0.1:8000) is host-reachable.
- DB passwords default to `*_dev_only`; rotate in `.env` if the volume leaves your machine.
- These containers run intentionally vulnerable code. Do not pull outgoing network traffic from them.
