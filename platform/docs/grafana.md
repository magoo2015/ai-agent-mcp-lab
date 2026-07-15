# Grafana Hardening v1

This document describes how Grafana is exposed, authenticated, and operated on the AI Security Engineering Platform after Hardening v1.

For stack overview and dashboards, see [observability.md](./observability.md). For trust boundaries, see [architecture.md](./architecture.md).

## Trust boundary

| Path | Exposure |
| ---- | -------- |
| Host port **3001** | **Closed** — not published in Compose |
| Nginx `http://<host>/grafana/` | **Current bootstrap entry** (HTTP until certificate activation) |
| Nginx TCP **443** | Published/reserved, but no active TLS listener during bootstrap |
| Grafana container `:3000` | Docker network only (`expose: "3000"`) |
| Prometheus `:9090` | Internal only — **not** proxied by Nginx |

Operators reach Grafana only through Nginx. Direct host access to Grafana’s container port is not available.

## Subpath hosting

Grafana is configured for the `/grafana/` subpath:

- `GF_SERVER_ROOT_URL` ← `GRAFANA_ROOT_URL` (Compose fallback `http://localhost/grafana/`)
- `GF_SERVER_SERVE_FROM_SUB_PATH=true`

Nginx proxies (preserve the `/grafana/` URI — do not use a trailing slash on `proxy_pass` when `SERVE_FROM_SUB_PATH=true`, or Grafana redirect-loops):

```nginx
location /grafana/ {
    proxy_pass http://grafana:3000;
    # Host / X-Forwarded-* / WebSocket headers — see nginx/default.conf
}
```

Redirects and asset URLs must stay under `/grafana/` (not escape to `/login` at the site root).

`.env.example` shows an HTTPS placeholder only. Keep the ignored local `platform/.env` aligned with the currently active origin; set `GRAFANA_ROOT_URL=https://<your-domain>/grafana/` only when the matching certificate and TLS Nginx configuration are activated. Recreate only the Grafana container so it reads the new URL; do not delete or reset the `grafana` volume.

## Administrator credentials

Compose requires a non-empty password:

```bash
GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD:?Set GRAFANA_ADMIN_PASSWORD in platform/.env}
```

Placeholders live in [`.env.example`](../.env.example). Real values belong only in `platform/.env` (gitignored).

| Variable | Role |
| -------- | ---- |
| `GRAFANA_ADMIN_USER` | Admin username (default `admin`) |
| `GRAFANA_ADMIN_PASSWORD` | **Required** admin password — never commit |
| `GRAFANA_ROOT_URL` | Public root URL for redirects/links |

Do not put passwords in docs, logs, or test output.

### Existing Grafana volumes and `GF_SECURITY_ADMIN_*`

Grafana applies `GF_SECURITY_ADMIN_USER` / `GF_SECURITY_ADMIN_PASSWORD` **only when the SQLite database is first initialized**. If the `grafana` volume already exists (this lab’s volume was created earlier), changing those environment variables does **not** reset the live admin password.

Hardening v1 does **not** delete the Grafana volume or dashboards. Before this phase, `admin` / `admin` already failed against the existing database (password was no longer the image default).

### Rotate the administrator password (safe procedure)

Prefer interactive reset so the password is not stored in shell history:

```bash
cd ~/projects/ai-agent-mcp-lab/platform
docker compose exec -it grafana grafana cli admin reset-admin-password --password-from-stdin
# Enter the new password when prompted (twice if asked)
```

Then update `GRAFANA_ADMIN_PASSWORD` in `platform/.env` to match (for documentation of the intended secret and for fresh installs). Do not commit `.env`.

Non-interactive alternative (password still appears in process list briefly — prefer stdin when possible):

```bash
docker compose exec grafana grafana cli admin reset-admin-password '<new-password>'
```

After rotation, confirm login at `http://<host>/grafana/` and that `/api/org` still requires authentication.

## Anonymous access and signup

| Setting | Value | Why |
| ------- | ----- | --- |
| `GF_AUTH_ANONYMOUS_ENABLED` | `false` | Dashboards and org APIs must not be readable without login |
| `GF_USERS_ALLOW_SIGN_UP` | `false` | Prevents unsolicited account creation on a public HTTP endpoint |

Normal username/password login remains enabled. OAuth/LDAP/IdP are out of scope for this phase.

## Prometheus data source

Grafana continues to query Prometheus on the Docker network:

```text
http://prometheus:9090
```

This lab already has a Prometheus data source stored in the Grafana volume. No public Prometheus proxy is added. Confirm reachability:

```bash
docker compose exec grafana wget -qO- http://prometheus:9090/-/healthy
```

## Resource limits

On this 2 vCPU / 4 GB VPS, Grafana is capped at:

| Limit | Value | Reasoning |
| ----- | ----- | --------- |
| `mem_limit` | `384m` | Observed steady-state ~126 MiB; 384m leaves headroom without starving Ollama/Open WebUI |
| `cpus` | `"0.50"` | Dashboard UI is bursty but not continuous; leaves CPU for inference and scrapers |

Revisit if Grafana OOMs or restart-loops under heavier dashboard load.

## Current limitations

- Traffic to `/grafana/` is still **HTTP** while TLS is in bootstrap mode.
- Port 443 is reserved for Nginx, but no HTTPS listener is active without a certificate.
- Conservative HTTPS headers are prepared in an inactive template. CSP and HSTS remain disabled until Open WebUI and Grafana compatibility, redirects, certificate trust, and renewal are validated.
- This is **not** production-ready Grafana; it is a hardened lab posture for a single-operator VPS.

## Next phase

- Configure a real public hostname and verify DNS plus ports 80/443.
- Complete staging and one production certificate issuance using [tls.md](./tls.md).
- Activate TLS termination and conservative security headers on Nginx.
- Update local `GRAFANA_ROOT_URL` to the matching HTTPS domain and verify login, subpath redirects, assets, and Grafana Live WebSockets.
