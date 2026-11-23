# admin.cubus.sh

Centralized, unprivileged administration and read-only observability web console for `cubus.sh`.

## Architecture

- **Privilege Separation:** Runs as a non-root (`65532:65532`), `read_only: true`, `scratch` Go binary with **no `/var/run/docker.sock` mount and no host filesystem mounts**.
- **Host & Stack Telemetry:** Queries `cubus.sh`'s internal-only `ops-agent` (`:9091`) over the `admin` network (`172.31.0.0/24`) for host CPU/RAM/disk/thermals, NVIDIA GPU telemetry, 1-hour metric history, container status/CPU/RAM, structured log search (including `nginx-proxy` JSON access logs), and SSE live log tailing.
- **PostgreSQL Overview:** Queries `db-broker`'s admin-only `GET /v1/admin/stats` endpoint for read-only database sizes and client connection counts.
- **Managed Services (`/admin/v1/*`):** Automatically discovers services labeled `cubus.admin.port` on the `admin` network, verifies their `admin_ip`, authenticates with per-service Bearer tokens (`ADMIN_TOKEN_<SERVICE>`), and dynamically renders capability tabs (`users`, schema-driven `settings`, `artifacts`) while recording every mutation to `audit_logs` in PostgreSQL (`svc_admin`).

## Authentication Modes

Set `AUTH_MODE` and `ADMIN_ALLOWED_EMAILS` in `.env`:

| `AUTH_MODE` | Behavior |
| :--- | :--- |
| `cloudflare` | Verifies `Cf-Access-Jwt-Assertion` (`RS256`/`ES256`) via Cloudflare Access JWKS (`CF_ACCESS_TEAM_DOMAIN`, `CF_ACCESS_AUD`). |
| `google` | App-hosted Google OAuth 2.0 / OIDC login (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`) with PKCE `S256`, single-use DB `oidc_transactions`, and DB-backed sessions. |
| `cloudflare_or_google` | Accepts a valid Cloudflare Access JWT when present; otherwise falls back to Google OAuth login. |
| `cloudflare_and_google` | Requires **both** a valid Cloudflare Access JWT **and** an active Google OAuth session (defense-in-depth). |

Every request re-checks the authenticated email against `ADMIN_ALLOWED_EMAILS`.

## Environment Variables

Copy `.env.example` to `.env`:

```sh
cp .env.example .env
```

| Variable | Required | Description |
| :--- | :--- | :--- |
| `AUTH_MODE` | Prod | `cloudflare`, `google`, `cloudflare_or_google`, or `cloudflare_and_google`. |
| `ADMIN_ALLOWED_EMAILS` | Yes | Comma-separated lowercase allowlist of permitted admin emails. |
| `CF_ACCESS_TEAM_DOMAIN` | If CF | Exact `https://<team>.cloudflareaccess.com` team origin. |
| `CF_ACCESS_AUD` | If CF | Cloudflare Access Application Audience (`AUD`) tag. |
| `GOOGLE_CLIENT_ID` | If Google | Google OAuth 2.0 Client ID (callback: `https://admin.cubus.sh/auth/google/callback`). |
| `GOOGLE_CLIENT_SECRET` | If Google | Google OAuth 2.0 Client Secret. |
| `ADMIN_TOKEN_<SERVICE>` | Per service | Bearer token for `<service>`'s internal `:9090` Admin API (e.g., `ADMIN_TOKEN_ARTIFACT`). |
| `ADMIN_STATIC_SERVICES` | No | Optional local-dev static service list (`artifact=http://127.0.0.1:9090`). |
| `DEV_AUTH_EMAIL` | Local only | Loopback-only development auto-login email (refused if `PUBLIC_BASE_URL` is non-loopback). |

Additional runtime variables injected by root `cubus.sh/docker-compose.yml`:
- `PUBLIC_BASE_URL`, `DB_BROKER_URL`, `DB_STATS_URL`, `OPS_AGENT_URL`, `ADMIN_NETWORK_CIDR` (`172.31.0.0/24`).

## Local Standalone Development

```sh
cp .env.example .env
docker compose up --build
```

Run Go tests locally (requires Go 1.27+):

```sh
go vet ./...
go test -v -race ./...
```
