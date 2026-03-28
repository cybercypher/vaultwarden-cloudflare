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

  echo ""
  echo -e "  Domain options:"
  echo -e "    ${BOLD}custom${NC}  — use your own domain (e.g. vault.yourdomain.com)"
  echo -e "    ${BOLD}default${NC} — use workers.dev / pages.dev subdomains"
  echo ""
  askd "Domain type (custom/default)" "custom"
  DOMAIN_TYPE="$REPLY"

  CUSTOM_DOMAIN=""
  if [ "$DOMAIN_TYPE" = "custom" ]; then
    ask "Your domain (e.g. vault.example.com): "
    CUSTOM_DOMAIN="$REPLY"
    DOMAIN="https://${CUSTOM_DOMAIN}"
  else
    DOMAIN="https://${WORKER_NAME}.$(npx wrangler whoami 2>/dev/null | grep -oP '\w+\.workers\.dev' || echo 'YOUR_SUBDOMAIN.workers.dev')"
    askd "Domain" "$DOMAIN"
    DOMAIN="$REPLY"
  fi

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
  echo -e "  Email is used for: invites, 2FA codes, password hints"
  echo ""
  askd "Enable email sending? (yes/no)" "yes"
  if [ "$REPLY" = "yes" ] || [ "$REPLY" = "true" ]; then
    MAIL_ENABLED="true"
  else
    MAIL_ENABLED="false"
  fi

  MAIL_BACKEND="cloudflare"
  MAIL_FROM="vaultwarden@yourdomain.com"
  MAIL_FROM_NAME="Vaultwarden"
  MAILGUN_DOMAIN=""
  HAS_MAIL_API_KEY=false
  USE_CF_EMAIL=false

  if [ "$MAIL_ENABLED" = "true" ]; then
    echo ""
    echo -e "  Email backends:"
    echo -e "    ${BOLD}cloudflare${NC}  — Cloudflare Email Workers (free, requires Email Routing on your domain)"
    echo -e "    ${BOLD}mailgun${NC}     — Mailgun API (1,000 free/month)"
    echo -e "    ${BOLD}resend${NC}      — Resend API (3,000 free/month)"
    echo -e "    ${BOLD}sendgrid${NC}    — SendGrid API (100 free/day)"
    echo ""

    if [ -n "$CUSTOM_DOMAIN" ]; then
      askd "Email backend" "cloudflare"
    else
      echo -e "  ${YELLOW}Note:${NC} Cloudflare Email Workers requires a custom domain with Email Routing."
      askd "Email backend" "mailgun"
    fi
    MAIL_BACKEND="$REPLY"

    # Extract domain from CUSTOM_DOMAIN or ask
    if [ -n "$CUSTOM_DOMAIN" ]; then
      # Get the root domain (e.g. vault.example.com → example.com)
      ROOT_DOMAIN=$(echo "$CUSTOM_DOMAIN" | awk -F. '{if(NF>2) print $(NF-1)"."$NF; else print $0}')
      askd "From email address" "vaultwarden@${ROOT_DOMAIN}"
    else
      askd "From email address" "vaultwarden@yourdomain.com"
    fi
    MAIL_FROM="$REPLY"

    askd "From display name" "Vaultwarden"
    MAIL_FROM_NAME="$REPLY"

    if [ "$MAIL_BACKEND" = "cloudflare" ]; then
      USE_CF_EMAIL=true
      # Extract domain from MAIL_FROM
      EMAIL_DOMAIN="${MAIL_FROM#*@}"
      echo ""
      echo -e "  ${BLUE}Cloudflare Email Workers setup requires:${NC}"
      echo -e "    1. Domain '${BOLD}${EMAIL_DOMAIN}${NC}' must be added to your Cloudflare account"
      echo -e "    2. Email Routing must be enabled on the domain"
      echo -e "       → Cloudflare Dashboard > ${EMAIL_DOMAIN} > Email > Email Routing > Enable"
      echo -e "    3. A verified destination email (your personal email)"
      echo ""
      ask "Press Enter when Email Routing is enabled (or 'skip' to configure later): "
      if [ "$REPLY" = "skip" ]; then
        warn "Email will be configured but won't work until Email Routing is enabled."
      fi

    elif [ "$MAIL_BACKEND" = "mailgun" ]; then
      askd "Mailgun domain (e.g. mg.yourdomain.com)" "mg.yourdomain.com"
      MAILGUN_DOMAIN="$REPLY"
      HAS_MAIL_API_KEY=true
      ask "Mailgun API key (will be stored as a secret): "
      MAIL_API_KEY="$REPLY"

    else
      # resend or sendgrid
      HAS_MAIL_API_KEY=true
      ask "${MAIL_BACKEND} API key (will be stored as a secret): "
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
  echo -e "${BOLD}── File Storage ──${NC}"
  echo ""
  echo -e "  File storage is used for vault attachments and Bitwarden Send files."
  echo -e "  Most users don't need this — passwords, logins, cards, notes are in the database."
  echo ""
  echo -e "    ${BOLD}kv${NC}  — Free, no credit card. 25MB per file, 1GB total. (recommended)"
  echo -e "    ${BOLD}r2${NC}  — Faster, 5GB free. May require credit card on Cloudflare."
  echo ""
  askd "File storage backend (kv/r2)" "kv"
  FILE_STORAGE="$REPLY"

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
  [ -n "$CUSTOM_DOMAIN" ] && echo -e "  Custom domain:   ${GREEN}${CUSTOM_DOMAIN}${NC}"
  echo -e "  Signups:         $([ "$SIGNUPS_ALLOWED" = "true" ] && echo "open" || echo "invite-only")"
  echo -e "  Email:           ${MAIL_ENABLED}$([ "$MAIL_ENABLED" = "true" ] && echo " (${MAIL_BACKEND})")"
  [ "$USE_CF_EMAIL" = true ] && echo -e "  Email domain:    ${MAIL_FROM#*@}"
  echo -e "  SSO:             ${SSO_ENABLED}$([ "$SSO_ENABLED" = "true" ] && echo " (${SSO_AUTHORITY})")"
  echo -e "  Admin panel:     $([ -n "$ADMIN_TOKEN" ] && echo "enabled" || echo "disabled")"
  echo -e "  Web vault:       $([ "$DEPLOY_VAULT" = "yes" ] && echo "${PAGES_PROJECT}" || echo "skip")"
  echo ""
  echo -e "  ${BOLD}Resources that will be created:${NC}"
  echo -e "    • D1 database: ${WORKER_NAME}"
  echo -e "    • KV namespace: ${WORKER_NAME}-kv"
  [ "$FILE_STORAGE" = "r2" ] && echo -e "    • R2 bucket: ${WORKER_NAME}-attachments"
  echo -e "    • Worker: ${WORKER_NAME}"
  [ "$DEPLOY_VAULT" = "yes" ] && echo -e "    • Pages project: ${PAGES_PROJECT}"
  [ -n "$CUSTOM_DOMAIN" ] && echo -e "    • Custom domain: ${CUSTOM_DOMAIN} (DNS records)"
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

  # R2 Bucket (only if using R2)
  if [ "$FILE_STORAGE" = "r2" ]; then
    info "Creating R2 bucket '${WORKER_NAME}-attachments'..."
    npx wrangler r2 bucket create "${WORKER_NAME}-attachments" 2>/dev/null || true
    ok "R2 bucket: ${WORKER_NAME}-attachments"
  else
    ok "File storage: KV (no R2 needed)"
  fi

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

[durable_objects]
bindings = [
  { name = "NOTIFICATION_HUB", class_name = "NotificationHub" }
]

[[migrations]]
tag = "v1"
new_classes = ["NotificationHub"]
TOMLEOF

  # Add R2 binding if using R2 for file storage
  if [ "$FILE_STORAGE" = "r2" ]; then
    cat >> wrangler.toml << TOMLEOF

[[r2_buckets]]
binding = "ATTACHMENTS"
bucket_name = "${WORKER_NAME}-attachments"
TOMLEOF
  fi

  # Add send_email binding if using Cloudflare Email Workers
  if [ "$USE_CF_EMAIL" = true ]; then
    cat >> wrangler.toml << 'TOMLEOF'

[[send_email]]
name = "SEND_EMAIL"
TOMLEOF
  fi

  # Add custom domain route if configured
  if [ -n "$CUSTOM_DOMAIN" ]; then
    cat >> wrangler.toml << TOMLEOF

[env.production]
routes = [
  { pattern = "${CUSTOM_DOMAIN}", custom_domain = true }
]
TOMLEOF
  fi

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
  # Determine the user-facing URL
  if [ -n "$CUSTOM_DOMAIN" ]; then
    USER_URL="https://${CUSTOM_DOMAIN}"
  elif [ -n "$PAGES_URL" ]; then
    USER_URL="${PAGES_URL}"
  else
    USER_URL="${WORKER_URL}"
  fi

  echo -e "  ${BOLD}Worker API:${NC}    ${WORKER_URL}"
  [ -n "$PAGES_URL" ] && echo -e "  ${BOLD}Web Vault:${NC}     ${PAGES_URL}"
  [ -n "$CUSTOM_DOMAIN" ] && echo -e "  ${BOLD}Custom URL:${NC}    https://${CUSTOM_DOMAIN}"
  echo -e "  ${BOLD}Admin Panel:${NC}   ${USER_URL}/admin"
  echo ""

  STEP=1
  echo -e "  ${BOLD}Next steps:${NC}"
  echo ""

  if [ -n "$CUSTOM_DOMAIN" ]; then
    echo -e "  ${STEP}. ${BOLD}Set up DNS for ${CUSTOM_DOMAIN}:${NC}"
    echo ""
    echo -e "     For the ${BOLD}Worker API${NC} (Bitwarden clients connect here):"
    echo -e "     In Cloudflare Dashboard > DNS > Add Record:"
    echo -e "       Type: ${BOLD}AAAA${NC}  Name: ${BOLD}${CUSTOM_DOMAIN%%.*}${NC}  Content: ${BOLD}100::${NC}  Proxy: ${BOLD}ON${NC}"
    echo -e "       (Cloudflare will route this to your Worker automatically)"
    echo ""
    if [ -n "$PAGES_URL" ]; then
      PAGES_SUBDOMAIN="${PAGES_PROJECT}.pages.dev"
      echo -e "     For the ${BOLD}Web Vault${NC} (browser access):"
      echo -e "     Option A: Use Pages URL directly: ${PAGES_URL}"
      echo -e "     Option B: Add custom domain to Pages project:"
      echo -e "       npx wrangler pages project edit ${PAGES_PROJECT} --custom-domain ${CUSTOM_DOMAIN}"
      echo ""
    fi
    STEP=$((STEP+1))
  fi

  if [ -n "$ADMIN_TOKEN" ] && [ "$SIGNUPS_ALLOWED" = "false" ]; then
    echo -e "  ${STEP}. ${BOLD}Invite your family:${NC}"
    echo -e "     Go to ${USER_URL}/admin → log in → Invite User"
    echo -e "     Enter each family member's email address"
    echo -e "     They can then register at ${USER_URL}"
    STEP=$((STEP+1))
  fi

  echo -e "  ${STEP}. ${BOLD}Configure Bitwarden clients:${NC}"
  echo -e "     In any Bitwarden client, tap the gear icon before logging in"
  echo -e "     Set 'Self-hosted' server URL to: ${BOLD}${USER_URL}${NC}"
  STEP=$((STEP+1))

  if [ "$USE_CF_EMAIL" = true ]; then
    EMAIL_DOMAIN="${MAIL_FROM#*@}"
    echo ""
    echo -e "  ${STEP}. ${BOLD}Verify Email Routing is working:${NC}"
    echo -e "     Go to admin panel → Diagnostics → SMTP Test"
    echo -e "     Enter your email and click Send Test Email"
    echo -e "     If it fails, check: Dashboard > ${EMAIL_DOMAIN} > Email > Email Routing"
    STEP=$((STEP+1))
  fi

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
