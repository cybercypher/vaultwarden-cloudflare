#!/usr/bin/env bash
# =============================================================================
# Vaultwarden on Cloudflare Workers — Interactive Deploy Script
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${BLUE}→${NC} $1"; }
ok()    { echo -e "${GREEN}✓${NC} $1"; }
warn()  { echo -e "${YELLOW}⚠${NC} $1"; }
err()   { echo -e "${RED}✗${NC} $1"; }
ask()   { echo -en "${BOLD}$1${NC}"; read -r REPLY; }
askd()  { echo -en "${BOLD}$1 ${NC}[${2}]: "; read -r REPLY; [ -z "$REPLY" ] && REPLY="$2"; }

banner() {
  echo ""
  echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║  ${BOLD}Vaultwarden on Cloudflare Workers — Deploy${NC}${BLUE}              ║${NC}"
  echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# Pre-checks
# ═══════════════════════════════════════════════════════════════════════════════
preflight() {
  info "Running pre-flight checks..."

  if ! command -v wrangler &>/dev/null && ! npx wrangler --version &>/dev/null 2>&1; then
    err "wrangler not found. Run: npm install -g wrangler"
    exit 1
  fi
  ok "wrangler found"

  if ! command -v cargo &>/dev/null; then
    err "cargo not found. Install Rust: https://rustup.rs"
    exit 1
  fi
  ok "cargo found"

  if ! rustup target list --installed | grep -q wasm32-unknown-unknown; then
    warn "wasm32-unknown-unknown target not installed. Installing..."
    rustup target add wasm32-unknown-unknown
  fi
  ok "wasm32 target ready"

  if ! command -v wasm-opt &>/dev/null && ! cargo install --list | grep -q wasm-opt; then
    warn "wasm-opt not found (optional but recommended for smaller binaries)"
  fi

  # Check wrangler auth
  if ! npx wrangler whoami &>/dev/null 2>&1; then
    warn "Not logged in to Cloudflare."
    info "Running: npx wrangler login"
    npx wrangler login
  fi
  ok "Cloudflare authenticated"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# Collect configuration
# ═══════════════════════════════════════════════════════════════════════════════
collect_config() {
  echo -e "${BOLD}── Worker Configuration ──${NC}"
  echo ""

  askd "Worker name" "vaultwarden"
  WORKER_NAME="$REPLY"

  askd "Domain (your worker URL, e.g. https://vaultwarden.you.workers.dev)" "https://${WORKER_NAME}.$(npx wrangler whoami 2>/dev/null | grep -oP '\w+\.workers\.dev' || echo 'YOUR_SUBDOMAIN.workers.dev')"
  DOMAIN="$REPLY"

  echo ""
  echo -e "  Signup modes:"
  echo -e "    ${BOLD}open${NC}        — anyone can create an account"
  echo -e "    ${BOLD}invite-only${NC} — only admin-invited emails can register"
  echo ""
  askd "Signup mode (open/invite-only)" "invite-only"
  if [ "$REPLY" = "open" ]; then
    SIGNUPS_ALLOWED="true"
  else
    SIGNUPS_ALLOWED="false"
  fi

  echo ""
  echo -e "${BOLD}── Email Configuration ──${NC}"
  echo ""
  askd "Enable email sending? (true/false)" "false"
  MAIL_ENABLED="$REPLY"

  MAIL_BACKEND="cloudflare"
  MAIL_FROM="vaultwarden@yourdomain.com"
  MAIL_FROM_NAME="Vaultwarden"
  MAILGUN_DOMAIN=""
  HAS_MAIL_API_KEY=false

  if [ "$MAIL_ENABLED" = "true" ]; then
    askd "Email backend (cloudflare/mailgun/sendgrid/resend)" "mailgun"
    MAIL_BACKEND="$REPLY"

    askd "From email address" "vaultwarden@yourdomain.com"
    MAIL_FROM="$REPLY"

    askd "From display name" "Vaultwarden"
    MAIL_FROM_NAME="$REPLY"

    if [ "$MAIL_BACKEND" = "mailgun" ]; then
      askd "Mailgun domain (e.g. mg.yourdomain.com)" "mg.yourdomain.com"
      MAILGUN_DOMAIN="$REPLY"
    fi

    if [ "$MAIL_BACKEND" != "cloudflare" ]; then
      HAS_MAIL_API_KEY=true
      ask "Mail API key (will be stored as a secret): "
      MAIL_API_KEY="$REPLY"
    fi
  fi

  echo ""
  echo -e "${BOLD}── SSO/OIDC Configuration ──${NC}"
  echo ""
  askd "Enable SSO? (true/false)" "false"
  SSO_ENABLED="$REPLY"

  SSO_CLIENT_ID=""
  SSO_AUTHORITY=""
  SSO_CLIENT_SECRET=""

  if [ "$SSO_ENABLED" = "true" ]; then
    askd "SSO Client ID" "vaultwarden"
    SSO_CLIENT_ID="$REPLY"

    ask "SSO Authority URL (e.g. https://auth.example.com/realms/master): "
    SSO_AUTHORITY="$REPLY"

    ask "SSO Client Secret (will be stored as a secret): "
    SSO_CLIENT_SECRET="$REPLY"
  fi

  echo ""
  echo -e "${BOLD}── Admin Panel ──${NC}"
  echo ""
  askd "Set an admin token? (leave blank to disable admin panel)" ""
  ADMIN_TOKEN="$REPLY"

  echo ""
  echo -e "${BOLD}── Web Vault (CF Pages) ──${NC}"
  echo ""
  askd "Deploy web vault to CF Pages? (yes/no)" "yes"
  DEPLOY_VAULT="$REPLY"

  PAGES_PROJECT="vaultwarden-vault"
  if [ "$DEPLOY_VAULT" = "yes" ]; then
    askd "Pages project name" "vaultwarden-vault"
    PAGES_PROJECT="$REPLY"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Show summary and confirm
# ═══════════════════════════════════════════════════════════════════════════════
confirm_deploy() {
  echo ""
  echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  Deployment Summary${NC}"
  echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "  Worker name:     ${GREEN}${WORKER_NAME}${NC}"
  echo -e "  Domain:          ${GREEN}${DOMAIN}${NC}"
  echo -e "  Signups:         ${SIGNUPS_ALLOWED}"
  echo -e "  Email:           ${MAIL_ENABLED}$([ "$MAIL_ENABLED" = "true" ] && echo " (${MAIL_BACKEND})")"
  echo -e "  SSO:             ${SSO_ENABLED}$([ "$SSO_ENABLED" = "true" ] && echo " (${SSO_AUTHORITY})")"
  echo -e "  Admin panel:     $([ -n "$ADMIN_TOKEN" ] && echo "enabled" || echo "disabled")"
  echo -e "  Web vault:       $([ "$DEPLOY_VAULT" = "yes" ] && echo "${PAGES_PROJECT}" || echo "skip")"
  echo ""
  echo -e "  ${BOLD}Resources that will be created:${NC}"
  echo -e "    • D1 database: ${WORKER_NAME}"
  echo -e "    • KV namespace: ${WORKER_NAME}-kv"
  echo -e "    • R2 bucket: ${WORKER_NAME}-attachments"
  echo -e "    • Worker: ${WORKER_NAME}"
  [ "$DEPLOY_VAULT" = "yes" ] && echo -e "    • Pages project: ${PAGES_PROJECT}"
  echo ""
  echo -e "  ${BOLD}Secrets that will be set:${NC}"
  echo -e "    • RSA_PRIVATE_KEY_PEM (auto-generated)"
  [ -n "$ADMIN_TOKEN" ] && echo -e "    • ADMIN_TOKEN"
  [ "$HAS_MAIL_API_KEY" = true ] && echo -e "    • MAIL_API_KEY"
  [ -n "$SSO_CLIENT_SECRET" ] && echo -e "    • SSO_CLIENT_SECRET"
  echo ""
  echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
  echo ""
  ask "Proceed with deployment? (yes/no): "
  if [ "$REPLY" != "yes" ]; then
    echo ""
    warn "Deployment cancelled."
    exit 0
  fi
  echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# Deploy
# ═══════════════════════════════════════════════════════════════════════════════
do_deploy() {
  echo -e "${BOLD}── Step 1/7: Create Cloudflare Resources ──${NC}"
  echo ""

  # D1 Database
  info "Creating D1 database '${WORKER_NAME}'..."
  D1_OUTPUT=$(npx wrangler d1 create "$WORKER_NAME" 2>&1) || true
  D1_ID=$(echo "$D1_OUTPUT" | grep -oP 'database_id\s*=\s*"\K[^"]+' || echo "")
  if [ -z "$D1_ID" ]; then
    # Already exists — fetch the ID
    D1_ID=$(npx wrangler d1 list 2>/dev/null | grep "$WORKER_NAME" | grep -oP '[0-9a-f-]{36}' | head -1 || echo "")
  fi
  if [ -z "$D1_ID" ]; then
    err "Could not create or find D1 database. Create it manually:"
    err "  npx wrangler d1 create ${WORKER_NAME}"
    exit 1
  fi
  ok "D1 database: ${D1_ID}"

  # KV Namespace
  info "Creating KV namespace '${WORKER_NAME}-kv'..."
  KV_OUTPUT=$(npx wrangler kv namespace create "${WORKER_NAME}-kv" 2>&1) || true
  KV_ID=$(echo "$KV_OUTPUT" | grep -oP 'id\s*=\s*"\K[^"]+' || echo "")
  if [ -z "$KV_ID" ]; then
    KV_ID=$(npx wrangler kv namespace list 2>/dev/null | grep -B1 "${WORKER_NAME}-kv" | grep -oP '"id":\s*"\K[^"]+' | head -1 || echo "")
  fi
  if [ -z "$KV_ID" ]; then
    err "Could not create or find KV namespace. Create it manually:"
    err "  npx wrangler kv namespace create ${WORKER_NAME}-kv"
    exit 1
  fi
  ok "KV namespace: ${KV_ID}"

  # R2 Bucket
  info "Creating R2 bucket '${WORKER_NAME}-attachments'..."
  npx wrangler r2 bucket create "${WORKER_NAME}-attachments" 2>/dev/null || true
  ok "R2 bucket: ${WORKER_NAME}-attachments"

  echo ""
  echo -e "${BOLD}── Step 2/7: Write wrangler.toml ──${NC}"
  echo ""

  # Build the SSO vars section
  SSO_VARS=""
  if [ "$SSO_ENABLED" = "true" ]; then
    SSO_VARS="SSO_CLIENT_ID = \"${SSO_CLIENT_ID}\"
SSO_AUTHORITY = \"${SSO_AUTHORITY}\""
  fi

  MAILGUN_VAR=""
  if [ -n "$MAILGUN_DOMAIN" ]; then
    MAILGUN_VAR="MAILGUN_DOMAIN = \"${MAILGUN_DOMAIN}\""
  fi

  cat > wrangler.toml << TOMLEOF
name = "${WORKER_NAME}"
main = "build/worker/shim.mjs"
compatibility_date = "2024-12-01"

[build]
command = "cargo install -q worker-build && worker-build --release"

[vars]
DOMAIN = "${DOMAIN}"
SIGNUPS_ALLOWED = "${SIGNUPS_ALLOWED}"
PASSWORD_ITERATIONS = "600000"
ACCESS_TOKEN_VALIDITY = "7200"
REFRESH_TOKEN_VALIDITY_DAYS = "30"
MAIL_ENABLED = "${MAIL_ENABLED}"
MAIL_BACKEND = "${MAIL_BACKEND}"
MAIL_FROM = "${MAIL_FROM}"
MAIL_FROM_NAME = "${MAIL_FROM_NAME}"
${MAILGUN_VAR}
SSO_ENABLED = "${SSO_ENABLED}"
${SSO_VARS}

[[d1_databases]]
binding = "DB"
database_name = "${WORKER_NAME}"
database_id = "${D1_ID}"

[[kv_namespaces]]
binding = "KV"
id = "${KV_ID}"

[[r2_buckets]]
binding = "ATTACHMENTS"
bucket_name = "${WORKER_NAME}-attachments"

[durable_objects]
bindings = [
  { name = "NOTIFICATION_HUB", class_name = "NotificationHub" }
]

[[migrations]]
tag = "v1"
new_classes = ["NotificationHub"]
TOMLEOF

  # Clean up empty lines from optional vars
  sed -i '/^$/d' wrangler.toml
  # Re-add a blank line before each section
  sed -i '/^\[/i\\' wrangler.toml

  ok "wrangler.toml written"

  echo ""
  echo -e "${BOLD}── Step 3/7: Run D1 Migration ──${NC}"
  echo ""

  info "Applying database schema..."
  npx wrangler d1 execute "$WORKER_NAME" --file=migrations/0001_initial.sql --remote 2>&1 | tail -3
  ok "Database schema applied"

  echo ""
  echo -e "${BOLD}── Step 4/7: Set Secrets ──${NC}"
  echo ""

  # Generate RSA key
  info "Generating RSA private key..."
  RSA_KEY=$(openssl genrsa 2048 2>/dev/null)
  echo "$RSA_KEY" | npx wrangler secret put RSA_PRIVATE_KEY_PEM 2>&1 | tail -1
  ok "RSA_PRIVATE_KEY_PEM set"

  if [ -n "$ADMIN_TOKEN" ]; then
    echo "$ADMIN_TOKEN" | npx wrangler secret put ADMIN_TOKEN 2>&1 | tail -1
    ok "ADMIN_TOKEN set"
  fi

  if [ "$HAS_MAIL_API_KEY" = true ] && [ -n "$MAIL_API_KEY" ]; then
    echo "$MAIL_API_KEY" | npx wrangler secret put MAIL_API_KEY 2>&1 | tail -1
    ok "MAIL_API_KEY set"
  fi

  if [ -n "$SSO_CLIENT_SECRET" ]; then
    echo "$SSO_CLIENT_SECRET" | npx wrangler secret put SSO_CLIENT_SECRET 2>&1 | tail -1
    ok "SSO_CLIENT_SECRET set"
  fi

  echo ""
  echo -e "${BOLD}── Step 5/7: Build Worker ──${NC}"
  echo ""

  info "Building Rust → WASM (this takes 1-3 minutes)..."
  worker-build --release 2>&1 | tail -5
  ok "Worker built"

  echo ""
  echo -e "${BOLD}── Step 6/7: Deploy Worker ──${NC}"
  echo ""

  info "Deploying to Cloudflare Workers..."
  DEPLOY_OUTPUT=$(npx wrangler deploy 2>&1)
  WORKER_URL=$(echo "$DEPLOY_OUTPUT" | grep -oP 'https://[^\s]+\.workers\.dev' | head -1 || echo "$DOMAIN")
  echo "$DEPLOY_OUTPUT" | tail -5
  ok "Worker deployed: ${WORKER_URL}"

  echo ""
  echo -e "${BOLD}── Step 7/7: Deploy Web Vault (CF Pages) ──${NC}"
  echo ""

  if [ "$DEPLOY_VAULT" = "yes" ]; then
    # Use the actual worker URL for redirects
    ACTUAL_URL="${WORKER_URL:-$DOMAIN}"
    info "Downloading and configuring web vault..."
    bash web-vault/setup.sh "$ACTUAL_URL" 2>&1 | grep "→\|Copied\|Created"
    echo ""

    info "Creating Pages project '${PAGES_PROJECT}'..."
    npx wrangler pages project create "$PAGES_PROJECT" --production-branch main 2>/dev/null || true

    info "Deploying to CF Pages..."
    PAGES_OUTPUT=$(npx wrangler pages deploy web-vault/build --project-name "$PAGES_PROJECT" 2>&1)
    PAGES_URL=$(echo "$PAGES_OUTPUT" | grep -oP 'https://[^\s]+\.pages\.dev' | head -1 || echo "")
    echo "$PAGES_OUTPUT" | tail -3
    ok "Web vault deployed: ${PAGES_URL}"
  else
    warn "Skipping web vault deployment"
    PAGES_URL=""
  fi

  # ═════════════════════════════════════════════════════════════════════════════
  # Done!
  # ═════════════════════════════════════════════════════════════════════════════
  echo ""
  echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}  Deployment Complete!${NC}"
  echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "  ${BOLD}Worker API:${NC}    ${WORKER_URL}"
  [ -n "$PAGES_URL" ] && echo -e "  ${BOLD}Web Vault:${NC}     ${PAGES_URL}"
  [ -n "$PAGES_URL" ] && echo -e "  ${BOLD}Admin Panel:${NC}   ${PAGES_URL}/admin"
  echo ""
  echo -e "  ${BOLD}Next steps:${NC}"
  echo ""
  if [ -n "$PAGES_URL" ]; then
    echo -e "  1. Open ${BOLD}${PAGES_URL}${NC} in your browser"
    echo -e "  2. Create an account and start using Bitwarden"
    echo -e "  3. Configure clients to use: ${BOLD}${PAGES_URL}${NC}"
  else
    echo -e "  1. Configure Bitwarden clients to use: ${BOLD}${WORKER_URL}${NC}"
  fi
  if [ -n "$ADMIN_TOKEN" ]; then
    echo -e "  4. Admin panel: ${BOLD}${PAGES_URL:-$WORKER_URL}/admin${NC}"
  fi
  echo ""
  echo -e "  ${BOLD}Custom domain:${NC}"
  echo -e "  To use your own domain, add a CNAME in Cloudflare DNS"
  echo -e "  and update DOMAIN in wrangler.toml, then redeploy."
  echo ""
  echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════
banner
preflight
collect_config
confirm_deploy
do_deploy
