# HTTPS/TLS Hardening v1

## Current status: bootstrap only

The repository is prepared for ACME HTTP-01 challenges, but HTTPS is **not active**. No valid public hostname is configured, so no staging or production certificate has been requested. Nginx continues to serve the existing application over HTTP while `/.well-known/acme-challenge/` is available for a future certificate request.

Do not activate `nginx/tls.conf.template` until the certificate files it references exist. Nginx will fail to start if a configured certificate is missing.

## Trust boundary

After activation, Internet traffic will enter only through Nginx on TCP 80/443. Nginx will terminate TLS and route:

- `/` to Open WebUI
- `/gateway/` to the AI Gateway
- `/grafana/` to Grafana

Open WebUI, the AI Gateway, Grafana, Prometheus, Ollama, and exporters remain on the internal Docker network. Gateway `/metrics`, Prometheus, Gateway port 8000, and Grafana port 3000 are not public. `/gateway/chat` continues to require `X-API-Key`; TLS does not replace application authentication.

## DNS and firewall prerequisites

Before requesting any certificate:

1. Put the real `PLATFORM_DOMAIN`, `CERTBOT_EMAIL`, and `GRAFANA_ROOT_URL=https://<domain>/grafana/` in the ignored `platform/.env`. Keep API keys and passwords unchanged.
2. Confirm the hostname is a real public DNS name, not `localhost` or an internal-only suffix.
3. Confirm its A/AAAA records resolve to this VPS. Remove an incorrect AAAA record rather than allowing IPv6 validation to reach another host.
4. Confirm inbound TCP 80 and 443 are allowed by UFW and the DigitalOcean Cloud Firewall.
5. Confirm an external request to `http://<domain>` reaches this Nginx instance.

Useful read-only checks:

```bash
getent hosts "$PLATFORM_DOMAIN"
sudo ufw status verbose
docker compose ps
curl -I "http://${PLATFORM_DOMAIN}/"
```

Compare the resolved address with the VPS public address in the DigitalOcean control panel. Test public reachability from a separate network; a request from the VPS alone does not prove Internet reachability. Do not reopen ports 3001, 8000, 9090, or 11434.

## Certificate storage

- `certbot/www/` is the shared HTTP-01 webroot.
- `certbot/conf/` stores Let's Encrypt certificates, private keys, renewal files, and ACME account data.
- Nginx mounts both locations read-only; the profile-gated Certbot container mounts them read/write.
- Git ignores all runtime content in both directories except `.gitkeep`.

Private keys, certificates, ACME account data, credentials, and `platform/.env` must never be committed or pasted into logs or documentation.

## Staging-first issuance

Run these commands only after the prerequisite gate passes. Export the real values in the operator shell without writing them into tracked files.

First confirm Compose and the active bootstrap server:

```bash
docker compose config
docker compose --profile ai --profile tls config
docker compose exec nginx nginx -t
```

Create a harmless file under `certbot/www/.well-known/acme-challenge/` and confirm it is returned over HTTP without a redirect, then remove the test file.

Use a distinct certificate name for the staging test so it cannot be confused with production:

```bash
docker compose --profile tls run --rm certbot certonly \
  --staging \
  --cert-name "${PLATFORM_DOMAIN}-staging" \
  --webroot \
  --webroot-path /var/www/certbot \
  --email "$CERTBOT_EMAIL" \
  --agree-tos \
  --no-eff-email \
  -d "$PLATFORM_DOMAIN"
```

After staging validation succeeds, remove only that staging lineage:

```bash
docker compose --profile tls run --rm certbot delete \
  --cert-name "${PLATFORM_DOMAIN}-staging" \
  --non-interactive
```

Then make one production request:

```bash
docker compose --profile tls run --rm certbot certonly \
  --cert-name "$PLATFORM_DOMAIN" \
  --webroot \
  --webroot-path /var/www/certbot \
  --email "$CERTBOT_EMAIL" \
  --agree-tos \
  --no-eff-email \
  -d "$PLATFORM_DOMAIN"
```

Do not repeat production issuance while debugging Nginx or DNS. Fix and revalidate the HTTP challenge path with staging first.

## Activate HTTPS only after issuance

`nginx/default.conf` is the active bootstrap configuration. `nginx/tls.conf.template` is intentionally inactive and uses `__PLATFORM_DOMAIN__` placeholders.

After the production certificate exists:

1. Verify `certbot/conf/live/<domain>/fullchain.pem` and `privkey.pem` exist without printing their contents.
2. In a reviewed repository change, render `nginx/tls.conf.template` with the validated hostname and replace the contents of `nginx/default.conf`, which is the file Compose mounts as the active server configuration. Replace every `__PLATFORM_DOMAIN__` occurrence; do not place certificate contents in the config.
3. Set local `GRAFANA_ROOT_URL=https://<domain>/grafana/`.
4. Recreate Grafana without deleting its volume, then reload/recreate Nginx.
5. Run `docker compose exec nginx nginx -t` before relying on the service.

The activated configuration serves ACME challenges over HTTP and redirects all other HTTP requests to the canonical HTTPS hostname. It accepts TLS 1.2 and TLS 1.3 only.

## Security headers and HSTS

The inactive TLS template adds:

- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-Frame-Options: SAMEORIGIN`
- a conservative `Permissions-Policy` disabling unused browser capabilities

Content Security Policy is omitted until Open WebUI and Grafana assets, API calls, and WebSockets can be tested. HSTS is also omitted because enabling it before HTTPS and renewal are reliable can lock browsers out of the site.

After all routes and renewal are stable, a later reviewed change may begin with:

```nginx
add_header Strict-Transport-Security "max-age=86400" always;
```

Do not add `includeSubDomains` or `preload` in this phase.

## Validation after activation

Confirm:

- HTTP redirects to `https://<domain>/` except the ACME path.
- The certificate SAN matches the hostname, its chain validates, and its expiration is reasonable.
- Open WebUI login, assets, streaming WebSockets, and redirects remain HTTPS with no mixed content.
- `/gateway/health` returns 200.
- `/gateway/chat` returns 401 without a key and 200 with a valid key; never print the key.
- Grafana returns 200 or a redirect that remains under `/grafana/`; anonymous API access is denied.
- `/metrics` and `/gateway/metrics` return 404 publicly.
- Prometheus still scrapes `http://ai-gateway:8000/metrics` internally.
- Only Nginx publishes application ports 80 and 443.
- Intended HTTPS security headers are present.

## Renewal

Manual renewal:

```bash
docker compose --profile tls run --rm certbot renew
docker compose exec nginx nginx -s reload
```

Validate renewal without changing the live certificate:

```bash
docker compose --profile tls run --rm certbot renew --dry-run
```

No cron job or systemd timer is added in this phase. A later phase may automate renewal and the Nginx reload.

## Troubleshooting

### Nginx reports missing certificate files

Return to the bootstrap configuration. Confirm the exact lineage under `certbot/conf/live/` and that the configured hostname matches it. Do not create a self-signed substitute automatically.

### ACME challenge redirects or returns the application

Keep the `/.well-known/acme-challenge/` location in the HTTP server before the catch-all redirect. Confirm Certbot and Nginx use the same `certbot/www` mount.

### Redirect loop

Confirm Nginx sends `X-Forwarded-Proto $scheme`, Grafana uses `https://<domain>/grafana/`, and the Grafana proxy preserves the `/grafana/` prefix.

### Open WebUI or Grafana breaks under HTTPS

Check browser developer tools for mixed content, blocked assets, failed WebSockets, and redirects to HTTP. Do not invent unsupported Open WebUI environment variables; first verify the forwarded Host and protocol headers.
