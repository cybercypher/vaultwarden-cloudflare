# Vaultwarden on Cloudflare Workers

A complete port of [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (alternative Bitwarden server) to run entirely on Cloudflare's free-tier infrastructure.

**30 Rust source files | 7,624 lines | 120 API routes | 146 E2E tests | 2.0 MB WASM binary**

## Architecture

```
Bitwarden Clients (Web/Desktop/Mobile/CLI/Browser Extension)
              │
              ▼
    ┌─────────────────────┐
    │  Cloudflare Worker   │  ◄─ Rust compiled to WASM
    │  (vaultwarden-cf)    │
    └──┬──────┬──────┬────┘
       │      │      │
       ▼      ▼      ▼
    ┌─────┐ ┌────┐ ┌────┐
    │ D1  │ │ KV │ │ R2 │    ◄─ All free tier
    │(SQL)│ │    │ │    │
    └─────┘ └────┘ └────┘
       │
       ▼
 ┌──────────────┐
 │Durable Object│  ◄─ WebSocket push (free tier)
 │(per-user WS) │
 └──────────────┘
```

| Original Component | Cloudflare Replacement | Cost |
|---------------------|----------------------|------|
| Rocket web framework | `worker` crate (Rust→WASM) | $0 |
| Diesel ORM + SQLite/PG/MySQL | **D1** (SQLite-compatible) | $0 |
| Filesystem storage | **R2** object storage | $0 |
| OpenSSL RSA | `rsa` crate (pure Rust) | $0 |
| tokio async runtime | Worker runtime | $0 |
| Background jobs | `#[event(scheduled)]` cron | $0 |
| SMTP email | **Email Workers** / HTTP APIs | $0 |
| WebSocket push | **Durable Objects** (hibernatable) | $0 |

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) with `wasm32-unknown-unknown` target
- [Node.js](https://nodejs.org/) 18+
- [Cloudflare account](https://dash.cloudflare.com/sign-up) (free)

```bash
# Install tools
rustup target add wasm32-unknown-unknown
cargo install worker-build
npm install

# Login to Cloudflare
npx wrangler login
```

### 1. Create Resources

```bash
# Create D1 database
npx wrangler d1 create vaultwarden
# → Copy database_id into wrangler.toml

# Create KV namespace
npx wrangler kv namespace create KV
# → Copy id into wrangler.toml

# Create R2 bucket
npx wrangler r2 bucket create vaultwarden-attachments
```

### 2. Configure

Edit `wrangler.toml` with your resource IDs and domain:

```toml
[vars]
DOMAIN = "https://vaultwarden.your-subdomain.workers.dev"
```

### 3. Set Secrets

```bash
# Generate and set RSA key (PKCS#8 or PKCS#1 format both work)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | npx wrangler secret put RSA_PRIVATE_KEY_PEM

# Set admin token
echo "your-admin-token" | npx wrangler secret put ADMIN_TOKEN
```

### 4. Deploy

```bash
# Run database migration
npx wrangler d1 execute vaultwarden --file=migrations/0001_initial.sql

# Deploy
npm run deploy
```

### 5. Configure Client

In any Bitwarden client, go to **Settings → Self-hosted** and set the server URL to your Worker URL.

## Features

### Complete Bitwarden API Compatibility

| Category | Endpoints | Status |
|----------|-----------|--------|
| **Identity** | Login (password/refresh/API key/SSO), prelogin, register | ✅ |
| **2FA** | TOTP authenticator, email 2FA, recovery codes | ✅ |
| **SSO/OIDC** | Authorization code flow with PKCE, auto-create users | ✅ |
| **Accounts** | Profile, password change, KDF, keys, API key, devices, delete | ✅ |
| **Vault Sync** | Full sync with all ciphers, folders, collections, sends | ✅ |
| **Ciphers** | CRUD, bulk delete/move, import, purge, soft delete/restore | ✅ |
| **Folders** | Full CRUD | ✅ |
| **Sends** | Text/file sends, public access with password, expiration | ✅ |
| **Attachments** | Upload/download via R2, v2 API | ✅ |
| **Organizations** | Create/delete, members invite/confirm/remove, collections | ✅ |
| **Emergency Access** | Invite/accept/confirm, initiate/approve/reject, view/takeover | ✅ |
| **WebSocket Push** | Real-time sync via Durable Objects, SignalR MessagePack | ✅ |
| **Email** | 4 backends (CF Email Workers, Resend, SendGrid, Mailgun) | ✅ |
| **Admin API** | User management, diagnostics, config, org overview | ✅ |
| **Events** | Client event collection, org event listing | ✅ |
| **Cron Jobs** | Purge expired sends, clean trashed ciphers | ✅ |

## Configuration Reference

### Environment Variables (`wrangler.toml` `[vars]`)

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | required | Full URL where the worker is deployed |
| `SIGNUPS_ALLOWED` | `"true"` | Allow new user registration |
| `PASSWORD_ITERATIONS` | `"600000"` | Server-side PBKDF2 iterations for password hashing |
| `ACCESS_TOKEN_VALIDITY` | `"7200"` | JWT access token lifetime in seconds |
| `REFRESH_TOKEN_VALIDITY_DAYS` | `"30"` | Refresh token lifetime in days |
| `MAIL_ENABLED` | `"false"` | Enable email sending |
| `MAIL_BACKEND` | `"cloudflare"` | Email backend: `cloudflare`, `resend`, `sendgrid`, `mailgun` |
| `MAIL_FROM` | `"vaultwarden@yourdomain.com"` | Sender email address |
| `MAIL_FROM_NAME` | `"Vaultwarden"` | Sender display name |
| `SSO_ENABLED` | `"false"` | Enable SSO/OIDC authentication |
| `SSO_CLIENT_ID` | - | OIDC client ID |
| `SSO_AUTHORITY` | - | OIDC issuer URL |
| `CORS_ALLOWED_ORIGIN` | `"*"` | CORS allowed origin |
| `MAILGUN_DOMAIN` | - | Mailgun sending domain |

### Secrets (`wrangler secret put`)

| Secret | Description |
|--------|-------------|
| `RSA_PRIVATE_KEY_PEM` | RSA private key for JWT signing (PKCS#1 or PKCS#8 PEM) |
| `ADMIN_TOKEN` | Admin panel authentication token |
| `MAIL_API_KEY` | API key for Resend/SendGrid/Mailgun |
| `SSO_CLIENT_SECRET` | OIDC client secret |

### Bindings

| Binding | Type | Description |
|---------|------|-------------|
| `DB` | D1 Database | Main database |
| `KV` | KV Namespace | 2FA tokens, SSO state |
| `ATTACHMENTS` | R2 Bucket | File attachments and send files |
| `NOTIFICATION_HUB` | Durable Object | WebSocket push notifications |

## Email Setup

### Cloudflare Email Workers (Free)
1. Enable Email Routing on your domain
2. Uncomment `[[send_email]]` in `wrangler.toml`
3. Set `MAIL_ENABLED = "true"`, `MAIL_BACKEND = "cloudflare"`

### Resend / SendGrid / Mailgun
```bash
npx wrangler secret put MAIL_API_KEY
```
Set `MAIL_BACKEND` to `resend`, `sendgrid`, or `mailgun`.

## SSO/OIDC Setup

1. Register client in your OIDC provider (Keycloak, Auth0, Okta, etc.)
2. Redirect URI: `https://your-worker.workers.dev/identity/connect/oidc-signin`
3. Set secrets and vars:
```bash
npx wrangler secret put SSO_CLIENT_SECRET
```
```toml
SSO_ENABLED = "true"
SSO_CLIENT_ID = "vaultwarden"
SSO_AUTHORITY = "https://auth.example.com/realms/master"
```

## Testing

```bash
# 146 end-to-end tests covering all API endpoints
npm run dev &
sleep 20
npx wrangler d1 execute vaultwarden --local --file=migrations/0001_initial.sql
bash tests/run_tests.sh http://localhost:8787
```

Tests cover: registration, prelogin, login (password/refresh/API key), profile CRUD, security stamp, folders CRUD, ciphers CRUD (create/read/update/delete/soft-delete/restore/move/import/purge), vault sync, sends (CRUD + public access), organizations (create/members/collections/delete), 2FA (TOTP/email), emergency access, equivalent domains, events, notifications, auth error handling, and full cleanup.

## Cloudflare Free Tier Limits

| Resource | Free Limit | Typical Personal Usage |
|----------|-----------|----------------------|
| Workers requests | 100K/day | ~100-1000/day |
| D1 reads | 5M rows/day | ~1000-5000/day |
| D1 writes | 100K rows/day | ~100-500/day |
| D1 storage | 5 GB | < 100 MB |
| R2 storage | 10 GB | Depends on attachments |
| Durable Objects | Free tier | 1 per user (hibernated) |

## Security Model

- **Zero-knowledge**: All encryption/decryption happens client-side
- **Double-hashed passwords**: Client PBKDF2/Argon2 → server PBKDF2 (600K iterations)
- **RSA-256 JWTs**: Private key stored as Cloudflare secret
- **2FA enforcement**: TOTP + email verified during login flow
- **Access control**: Per-cipher ownership + organization membership validation
- **Security stamp rotation**: Invalidates all sessions on password change
- **Constant-time comparison**: For all password and token checks
- **Configurable CORS**: Restrict to your vault domain

## License

AGPL-3.0 (same as original Vaultwarden)
