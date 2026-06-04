# ModSecurity + OWASP CRS

This WAF uses the official [`owasp/modsecurity-crs:nginx-alpine`](https://github.com/coreruleset/modsecurity-crs-docker) image directly — no Dockerfile is needed. The image bundles ModSecurity v3, the OWASP CRS v4, and nginx as the HTTP layer.

## Pinned tag

Phase 1 uses `owasp/modsecurity-crs:4.25.0-nginx-alpine-202604040104`. Update in `docker-compose.yml` when bumping — never use `latest`.

## Tunables (env vars)

| Env var | Default | Notes |
|---|---|---|
| `PARANOIA` | `1` | Paper baseline; raise via `--profile paranoia-high` (sets `4`) |
| `ANOMALY_INBOUND` | `5` | Block threshold |
| `ANOMALY_OUTBOUND` | `4` | Response-side block threshold |
| `MODSEC_RULE_ENGINE` | `On` | Also accepts `DetectionOnly` |
| `BACKEND` | — | Required; proxy upstream (Phase 1: `http://whoami:80`) |

Full env contract: see the image's README.
