#!/usr/bin/env bash
# =============================================================================
# Bitwarden Web Vault - Cloudflare Pages Setup
#
# Downloads the patched web vault from bw_web_builds, configures it to point
# at your vaultwarden CF Worker API, and deploys to CF Pages.
#
# Usage:
#   ./web-vault/setup.sh <WORKER_URL>
#
# Example:
#   ./web-vault/setup.sh https://vaultwarden.your-subdomain.workers.dev
#
# After running, deploy with:
#   npx wrangler pages deploy web-vault/build --project-name vaultwarden-vault
# =============================================================================
set -euo pipefail

WORKER_URL="${1:-}"
if [ -z "$WORKER_URL" ]; then
    echo "Usage: ./web-vault/setup.sh <WORKER_URL>"
    echo "Example: ./web-vault/setup.sh https://vaultwarden.your-subdomain.workers.dev"
    exit 1
fi

# Remove trailing slash
WORKER_URL="${WORKER_URL%/}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
WEB_VAULT_VERSION="v2026.1.1"
DOWNLOAD_URL="https://github.com/dani-garcia/bw_web_builds/releases/download/${WEB_VAULT_VERSION}/bw_web_${WEB_VAULT_VERSION}.tar.gz"

echo "════════════════════════════════════════════════════════════"
echo "  Bitwarden Web Vault Setup for Cloudflare Pages"
echo "  Worker API URL: ${WORKER_URL}"
echo "  Web Vault Version: ${WEB_VAULT_VERSION}"
echo "════════════════════════════════════════════════════════════"
echo ""

# Step 1: Download
echo "→ Downloading web vault..."
mkdir -p "${SCRIPT_DIR}/tmp"
TARBALL="${SCRIPT_DIR}/tmp/bw_web.tar.gz"
if [ ! -f "$TARBALL" ]; then
    curl -sL "$DOWNLOAD_URL" -o "$TARBALL"
    echo "  Downloaded $(du -h "$TARBALL" | cut -f1)"
else
    echo "  Using cached download"
fi

# Step 2: Extract
echo "→ Extracting..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
tar xzf "$TARBALL" -C "$BUILD_DIR" --strip-components=1
echo "  Extracted $(find "$BUILD_DIR" -type f | wc -l) files"

# Step 3: Configure API URL
echo "→ Configuring API endpoint..."

# The web vault reads config from app-id.json and has environment settings
# embedded in the JS. We need to patch the API URL in the compiled JS files.
# The web vault looks for the API base URL in several places.

# Method 1: Create/update the environment config
# The bw_web_builds already patches the vault to read from the same origin,
# so if Pages is on a different domain, we need a redirect or config override.

# Create a _headers file for CF Pages to set CORS
cat > "${BUILD_DIR}/_headers" << EOF
/*
  Access-Control-Allow-Origin: *
  Access-Control-Allow-Methods: GET, OPTIONS
  Access-Control-Allow-Headers: Content-Type
EOF

# Copy admin panel HTML
cp "${SCRIPT_DIR}/admin.html" "${BUILD_DIR}/admin/index.html" 2>/dev/null || {
  mkdir -p "${BUILD_DIR}/admin"
  cp "${SCRIPT_DIR}/admin.html" "${BUILD_DIR}/admin/index.html"
}
echo "  Copied admin panel"

# Create a _redirects file to proxy API requests to the Worker
# CF Pages supports proxying via _redirects with 200 status (rewrite)
# Note: /admin is served from Pages (the HTML), /admin/* API calls proxy to Worker
cat > "${BUILD_DIR}/_redirects" << EOF
/api/* ${WORKER_URL}/api/:splat 200
/identity/* ${WORKER_URL}/identity/:splat 200
/notifications/* ${WORKER_URL}/notifications/:splat 200
/admin/users/* ${WORKER_URL}/admin/users/:splat 200
/admin/organizations/* ${WORKER_URL}/admin/organizations/:splat 200
/admin/diagnostics/* ${WORKER_URL}/admin/diagnostics/:splat 200
/admin/diagnostics ${WORKER_URL}/admin/diagnostics 200
/admin/invite ${WORKER_URL}/admin/invite 200
/admin/test/* ${WORKER_URL}/admin/test/:splat 200
/admin/config/* ${WORKER_URL}/admin/config/:splat 200
/admin/config ${WORKER_URL}/admin/config 200
/admin/logout ${WORKER_URL}/admin/logout 200
/attachments/* ${WORKER_URL}/attachments/:splat 200
/alive ${WORKER_URL}/alive 200
EOF
# Note: POST /admin (login API) is proxied because _redirects applies to all methods
# when no static file matches. GET /admin serves admin/index.html (static file priority).

echo "  Created _redirects to proxy API calls to ${WORKER_URL}"

# Method 2: Also set the environment in the app config
# Find and patch the main JS bundle to set the API URL
# The web vault uses window.location.origin as the default API URL,
# which with _redirects proxying will work correctly since /api/* is rewritten.

# Create app-id.json (required by Bitwarden clients for FIDO2)
cat > "${BUILD_DIR}/app-id.json" << EOF
{
  "trustedFacets": [
    {
      "version": { "major": 2, "minor": 0 },
      "ids": [
        "${WORKER_URL}",
        "ios:bundle-id:com.8bit.bitwarden",
        "android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WXFyKae62LMe1QNLOB/YKIM"
      ]
    }
  ]
}
EOF

echo "  Created app-id.json"

# Step 4: Summary
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Setup complete!"
echo ""
echo "  Web vault files: ${BUILD_DIR}/"
echo "  File count: $(find "$BUILD_DIR" -type f | wc -l)"
echo "  Total size: $(du -sh "$BUILD_DIR" | cut -f1)"
echo ""
echo "  Deploy to CF Pages with:"
echo "    npx wrangler pages project create vaultwarden-vault"
echo "    npx wrangler pages deploy web-vault/build --project-name vaultwarden-vault"
echo ""
echo "  Then configure your Bitwarden clients to use the Pages URL"
echo "  (e.g., https://vaultwarden-vault.pages.dev)"
echo ""
echo "  The _redirects file proxies all API calls to your Worker:"
echo "    ${WORKER_URL}"
echo "════════════════════════════════════════════════════════════"
