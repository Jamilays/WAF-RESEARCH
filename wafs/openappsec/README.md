# open-appsec — real ML WAF integration (Phase 7)

Check Point's [open-appsec](https://www.openappsec.io/) is an open-source,
ML-based WAF. Unlike CRS-based WAFs (ModSec / Coraza) which rely on
pattern signatures, open-appsec uses a pre-trained model of benign traffic
plus attack features to classify incoming requests.

This directory wires the real agent into the lab as the **fourth WAF** —
replacing the `traefik/whoami` stubs that previously stood in under
`--profile ml`.

## Layout

```
wafs/openappsec/
├── README.md
├── localconfig/
│   └── local_policy.yaml          # prevent-learn mode, confidence=critical
├── nginx-config/
│   └── default.conf               # three server blocks, one per target
└── {config,data,logs,smartsync-storage,postgres-data}/
                                   # bind-mounted runtime state (gitignored)
```

## Topology

One container (`agent-unified`) ships NGINX **and** the open-appsec
attachment module in a single process. It multiplexes by `Host` header:

- `openappsec-dvwa.local`      → `dvwa:80`
- `openappsec-webgoat.local`   → `webgoat:8080`
- `openappsec-juiceshop.local` → `juiceshop:3000`

The standalone profile adds:

| Service | Image | Role |
|---|---|---|
| `appsec-smartsync` | `ghcr.io/openappsec/smartsync:latest` | online learning sync |
| `appsec-shared-storage` | `ghcr.io/openappsec/smartsync-shared-files:latest` | learner-state storage |
| `appsec-tuning-svc` | `ghcr.io/openappsec/smartsync-tuning:latest` | tuning service |
| `appsec-db` | `postgres:18` | tuning DB |

All four are gated behind compose's `COMPOSE_PROFILES=standalone` so a
managed-cloud deployment can skip them. In the lab we always run them
(via `docker compose --profile ml up`) so the agent has learning state
and the bypass-rate comparison is apples-to-apples with the other WAFs.

## Training / warm-up

Pre-trained out of the box. The "-learn" suffix on `prevent-learn` mode
keeps the online model updating as new traffic arrives. For the
lab's purposes this is fine — we don't rely on per-site tuning, the
baseline pre-trained model is what we compare against.

## Enforcement

`local_policy.yaml` sets:

```yaml
web-attacks:
  minimum-confidence: critical
  override-mode: prevent-learn
```

`critical` is the strictest confidence bucket (fewest false positives,
most missed attacks). Drop to `high` / `medium` / `low` in a follow-up
run to see the bypass-rate ↔ FP-rate tradeoff — the paper's Table 1
equivalent for ML-based WAFs.

## Probes

```bash
# Benign — should return 200 (passes through to Juice Shop)
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Host: openappsec-juiceshop.local' \
  'http://127.0.0.1:8000/rest/products/search?q=apple'

# Attack — should return 403 (blocked by agent)
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Host: openappsec-juiceshop.local' \
  "http://127.0.0.1:8000/rest/products/search?q=1' UNION SELECT 1--"
```

## Future work

- Tune minimum-confidence across the four levels and report the curve
- Expose the agent's threat-log fields in the dashboard (currently only
  the 403 status is captured)
- Investigate `snort-signatures` mode — optional dynamic rule injection
  alongside the ML model
