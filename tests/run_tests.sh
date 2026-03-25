#!/usr/bin/env bash
# =============================================================================
# Vaultwarden CF Workers - End-to-End Test Suite
#
# Tests all API endpoints against a running worker instance.
# Usage:
#   ./tests/run_tests.sh [BASE_URL]
#
# If no BASE_URL is provided, defaults to http://localhost:8787
# =============================================================================
set -euo pipefail

BASE_URL="${1:-http://localhost:8787}"
PASS=0
FAIL=0
SKIP=0
TOTAL=0
FAILURES=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test state (populated during test run)
ACCESS_TOKEN=""
REFRESH_TOKEN=""
USER_UUID=""
DEVICE_UUID=""
CIPHER_UUID=""
FOLDER_UUID=""
SEND_UUID=""
ORG_UUID=""
MEMBER_UUID=""
COLLECTION_UUID=""

# =============================================================================
# Test Helpers
# =============================================================================

assert_status() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    local body="${4:-}"
    TOTAL=$((TOTAL + 1))

    if [ "$actual" -eq "$expected" ]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} $test_name (HTTP $actual)"
    else
        FAIL=$((FAIL + 1))
        FAILURES="${FAILURES}\n  ${RED}✗${NC} $test_name: expected $expected, got $actual"
        echo -e "  ${RED}✗${NC} $test_name: expected HTTP $expected, got HTTP $actual"
        if [ -n "$body" ]; then
            echo "    Response: $(echo "$body" | head -c 200)"
        fi
    fi
}

assert_json_field() {
    local test_name="$1"
    local body="$2"
    local field="$3"
    local expected="$4"
    TOTAL=$((TOTAL + 1))

    local actual
    actual=$(echo "$body" | jq -r "$field" 2>/dev/null || echo "PARSE_ERROR")

    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} $test_name ($field = $expected)"
    else
        FAIL=$((FAIL + 1))
        FAILURES="${FAILURES}\n  ${RED}✗${NC} $test_name: $field expected '$expected', got '$actual'"
        echo -e "  ${RED}✗${NC} $test_name: $field expected '$expected', got '$actual'"
    fi
}

assert_json_exists() {
    local test_name="$1"
    local body="$2"
    local field="$3"
    TOTAL=$((TOTAL + 1))

    local actual
    actual=$(echo "$body" | jq -r "$field" 2>/dev/null || echo "null")

    if [ "$actual" != "null" ] && [ "$actual" != "" ]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} $test_name ($field exists)"
    else
        FAIL=$((FAIL + 1))
        FAILURES="${FAILURES}\n  ${RED}✗${NC} $test_name: $field is missing or null"
        echo -e "  ${RED}✗${NC} $test_name: $field is missing or null"
    fi
}

curl_get() {
    local path="$1"
    local token="${2:-}"
    local headers=(-s -w "\n%{http_code}")
    if [ -n "$token" ]; then
        headers+=(-H "Authorization: Bearer $token")
    fi
    curl "${headers[@]}" "${BASE_URL}${path}"
}

curl_post() {
    local path="$1"
    local data="$2"
    local token="${3:-}"
    local content_type="${4:-application/json}"
    local headers=(-s -w "\n%{http_code}" -H "Content-Type: $content_type")
    if [ -n "$token" ]; then
        headers+=(-H "Authorization: Bearer $token")
    fi
    curl "${headers[@]}" -X POST -d "$data" "${BASE_URL}${path}"
}

curl_put() {
    local path="$1"
    local data="$2"
    local token="${3:-}"
    local headers=(-s -w "\n%{http_code}" -H "Content-Type: application/json")
    if [ -n "$token" ]; then
        headers+=(-H "Authorization: Bearer $token")
    fi
    curl "${headers[@]}" -X PUT -d "$data" "${BASE_URL}${path}"
}

curl_delete() {
    local path="$1"
    local token="${2:-}"
    local data="${3:-}"
    local headers=(-s -w "\n%{http_code}")
    if [ -n "$token" ]; then
        headers+=(-H "Authorization: Bearer $token")
    fi
    if [ -n "$data" ]; then
        headers+=(-H "Content-Type: application/json" -d "$data")
    fi
    curl "${headers[@]}" -X DELETE "${BASE_URL}${path}"
}

parse_response() {
    local response="$1"
    BODY=$(echo "$response" | sed '$d')
    STATUS=$(echo "$response" | tail -1)
}

section() {
    echo ""
    echo -e "${BLUE}═══ $1 ═══${NC}"
}

# =============================================================================
# Test Suites
# =============================================================================

test_health() {
    section "Health & Config"

    parse_response "$(curl_get "/api/alive")"
    assert_status "GET /api/alive" 200 "$STATUS"

    parse_response "$(curl_get "/api/now")"
    assert_status "GET /api/now" 200 "$STATUS"

    parse_response "$(curl_get "/api/config")"
    assert_status "GET /api/config" 200 "$STATUS"
    assert_json_field "config has version" "$BODY" ".version" "2024.12.0"
    assert_json_exists "config has environment" "$BODY" ".environment.vault"

    parse_response "$(curl_get "/api/version")"
    assert_status "GET /api/version" 200 "$STATUS"

    parse_response "$(curl_get "/api/plans")"
    assert_status "GET /api/plans" 200 "$STATUS"
    assert_json_field "plans is list" "$BODY" ".object" "list"
}

test_cors() {
    section "CORS"

    local response
    response=$(curl -s -w "\n%{http_code}" -X OPTIONS \
        -H "Origin: https://vault.example.com" \
        -H "Access-Control-Request-Method: POST" \
        "${BASE_URL}/api/sync")
    parse_response "$response"
    assert_status "OPTIONS preflight returns 200" 200 "$STATUS"

    # Check CORS headers
    local cors_headers
    cors_headers=$(curl -sI -X OPTIONS "${BASE_URL}/api/sync" 2>/dev/null)
    TOTAL=$((TOTAL + 1))
    if echo "$cors_headers" | grep -qi "access-control-allow-origin"; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} CORS headers present"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}✗${NC} CORS headers missing"
    fi
}

test_register() {
    section "Registration"

    # Register a test user
    local register_data='{"email":"test@example.com","masterPasswordHash":"hash123","key":"enckey123","name":"Test User","kdf":0,"kdfIterations":600000}'
    parse_response "$(curl_post "/identity/accounts/register" "$register_data")"
    assert_status "POST /identity/accounts/register" 200 "$STATUS"

    # Register duplicate should fail
    parse_response "$(curl_post "/identity/accounts/register" "$register_data")"
    assert_status "duplicate registration rejected" 400 "$STATUS"

    # Register via /api/accounts/register
    local register_data2='{"email":"test2@example.com","masterPasswordHash":"hash456","key":"enckey456","name":"Test User 2","kdf":0,"kdfIterations":600000}'
    parse_response "$(curl_post "/api/accounts/register" "$register_data2")"
    assert_status "POST /api/accounts/register" 200 "$STATUS"
}

test_prelogin() {
    section "Prelogin"

    parse_response "$(curl_post "/identity/accounts/prelogin" '{"email":"test@example.com"}')"
    assert_status "POST prelogin known user" 200 "$STATUS"
    assert_json_field "kdf type" "$BODY" ".kdf" "0"
    assert_json_field "kdf iterations" "$BODY" ".kdfIterations" "600000"

    parse_response "$(curl_post "/identity/accounts/prelogin" '{"email":"unknown@example.com"}')"
    assert_status "POST prelogin unknown user (no leak)" 200 "$STATUS"
    assert_json_field "default kdf for unknown" "$BODY" ".kdf" "0"
}

test_login() {
    section "Login (Password Grant)"

    local login_data="grant_type=password&username=test@example.com&password=hash123&client_id=web&scope=api+offline_access&deviceIdentifier=test-device-001&deviceName=TestBrowser&deviceType=7"
    parse_response "$(curl_post "/identity/connect/token" "$login_data" "" "application/x-www-form-urlencoded")"
    assert_status "POST password login" 200 "$STATUS"
    assert_json_exists "has access_token" "$BODY" ".access_token"
    assert_json_exists "has refresh_token" "$BODY" ".refresh_token"
    assert_json_field "token_type is Bearer" "$BODY" ".token_type" "Bearer"
    assert_json_exists "has Key" "$BODY" ".Key"
    assert_json_exists "has Kdf" "$BODY" ".Kdf"
    assert_json_field "is unofficial" "$BODY" ".unofficialServer" "true"

    ACCESS_TOKEN=$(echo "$BODY" | jq -r ".access_token")
    REFRESH_TOKEN=$(echo "$BODY" | jq -r ".refresh_token")

    # Wrong password
    local bad_login="grant_type=password&username=test@example.com&password=wronghash&client_id=web&scope=api&deviceIdentifier=d1&deviceName=Test&deviceType=7"
    parse_response "$(curl_post "/identity/connect/token" "$bad_login" "" "application/x-www-form-urlencoded")"
    assert_status "wrong password rejected" 400 "$STATUS"

    # Missing fields
    parse_response "$(curl_post "/identity/connect/token" "grant_type=password" "" "application/x-www-form-urlencoded")"
    assert_status "missing fields rejected" 400 "$STATUS"
}

test_refresh() {
    section "Login (Refresh Grant)"

    local refresh_data="grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}"
    parse_response "$(curl_post "/identity/connect/token" "$refresh_data" "" "application/x-www-form-urlencoded")"
    assert_status "POST refresh login" 200 "$STATUS"
    assert_json_exists "refreshed access_token" "$BODY" ".access_token"

    # Update token for subsequent tests
    ACCESS_TOKEN=$(echo "$BODY" | jq -r ".access_token")
}

test_profile() {
    section "Accounts / Profile"

    parse_response "$(curl_get "/api/accounts/profile" "$ACCESS_TOKEN")"
    assert_status "GET profile" 200 "$STATUS"
    assert_json_field "profile email" "$BODY" ".email" "test@example.com"
    assert_json_field "profile name" "$BODY" ".name" "Test User"
    assert_json_field "profile object" "$BODY" ".object" "profile"
    assert_json_exists "profile has id" "$BODY" ".id"
    USER_UUID=$(echo "$BODY" | jq -r ".id")

    # Update profile
    parse_response "$(curl_put "/api/accounts/profile" '{"name":"Updated Name"}' "$ACCESS_TOKEN")"
    assert_status "PUT profile" 200 "$STATUS"
    assert_json_field "updated name" "$BODY" ".name" "Updated Name"

    # Revision date
    parse_response "$(curl_get "/api/accounts/revision-date" "$ACCESS_TOKEN")"
    assert_status "GET revision-date" 200 "$STATUS"

    # Verify password
    parse_response "$(curl_post "/api/accounts/verify-password" '{"masterPasswordHash":"hash123"}' "$ACCESS_TOKEN")"
    assert_status "POST verify-password (correct)" 200 "$STATUS"

    parse_response "$(curl_post "/api/accounts/verify-password" '{"masterPasswordHash":"wrong"}' "$ACCESS_TOKEN")"
    assert_status "POST verify-password (wrong)" 400 "$STATUS"

    # Password hint
    parse_response "$(curl_post "/api/accounts/password-hint" '{"email":"test@example.com"}')"
    assert_status "POST password-hint" 200 "$STATUS"

    # Devices
    parse_response "$(curl_get "/api/devices" "$ACCESS_TOKEN")"
    assert_status "GET devices" 200 "$STATUS"
    assert_json_field "devices is list" "$BODY" ".object" "list"

    # Collections
    parse_response "$(curl_get "/api/collections" "$ACCESS_TOKEN")"
    assert_status "GET collections" 200 "$STATUS"

    # Tasks
    parse_response "$(curl_get "/api/tasks" "$ACCESS_TOKEN")"
    assert_status "GET tasks" 200 "$STATUS"

    # Known device
    parse_response "$(curl_get "/api/devices/knowndevice" "$ACCESS_TOKEN")"
    assert_status "GET known device" 200 "$STATUS"
}

test_api_key() {
    section "API Key"

    parse_response "$(curl_post "/api/accounts/api-key" '{"masterPasswordHash":"hash123"}' "$ACCESS_TOKEN")"
    assert_status "POST get api-key" 200 "$STATUS"
    assert_json_exists "has apiKey" "$BODY" ".apiKey"

    local api_key
    api_key=$(echo "$BODY" | jq -r ".apiKey")

    parse_response "$(curl_post "/api/accounts/rotate-api-key" '{"masterPasswordHash":"hash123"}' "$ACCESS_TOKEN")"
    assert_status "POST rotate api-key" 200 "$STATUS"
    local new_api_key
    new_api_key=$(echo "$BODY" | jq -r ".apiKey")
    TOTAL=$((TOTAL + 1))
    if [ "$api_key" != "$new_api_key" ]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} API key was rotated"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}✗${NC} API key was not rotated"
    fi

    # Client credentials login with API key
    local api_login="grant_type=client_credentials&client_id=user.${USER_UUID}&client_secret=${new_api_key}&scope=api&deviceIdentifier=api-test&deviceName=APIClient&deviceType=21"
    parse_response "$(curl_post "/identity/connect/token" "$api_login" "" "application/x-www-form-urlencoded")"
    assert_status "POST client_credentials login" 200 "$STATUS"
    assert_json_exists "API login has access_token" "$BODY" ".access_token"
}

test_security_stamp() {
    section "Security Stamp"

    parse_response "$(curl_post "/api/accounts/security-stamp" '{"masterPasswordHash":"hash123"}' "$ACCESS_TOKEN")"
    assert_status "POST security-stamp" 200 "$STATUS"

    # Re-login since stamp changed (old token may be invalid for stamp-validated endpoints)
    local login_data="grant_type=password&username=test@example.com&password=hash123&client_id=web&scope=api+offline_access&deviceIdentifier=test-device-001&deviceName=TestBrowser&deviceType=7"
    parse_response "$(curl_post "/identity/connect/token" "$login_data" "" "application/x-www-form-urlencoded")"
    ACCESS_TOKEN=$(echo "$BODY" | jq -r ".access_token")
    REFRESH_TOKEN=$(echo "$BODY" | jq -r ".refresh_token")
}

test_folders() {
    section "Folders"

    # Create folder
    parse_response "$(curl_post "/api/folders" '{"name":"encrypted-folder-name"}' "$ACCESS_TOKEN")"
    assert_status "POST create folder" 200 "$STATUS"
    assert_json_field "folder object" "$BODY" ".object" "folder"
    assert_json_exists "folder has id" "$BODY" ".id"
    FOLDER_UUID=$(echo "$BODY" | jq -r ".id")

    # Get folder
    parse_response "$(curl_get "/api/folders/${FOLDER_UUID}" "$ACCESS_TOKEN")"
    assert_status "GET folder" 200 "$STATUS"
    assert_json_field "folder name" "$BODY" ".name" "encrypted-folder-name"

    # List folders
    parse_response "$(curl_get "/api/folders" "$ACCESS_TOKEN")"
    assert_status "GET folders list" 200 "$STATUS"
    assert_json_field "folders is list" "$BODY" ".object" "list"
    TOTAL=$((TOTAL + 1))
    local count
    count=$(echo "$BODY" | jq '.data | length')
    if [ "$count" -ge 1 ]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} folders list has $count items"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}✗${NC} folders list is empty"
    fi

    # Update folder
    parse_response "$(curl_put "/api/folders/${FOLDER_UUID}" '{"name":"updated-folder"}' "$ACCESS_TOKEN")"
    assert_status "PUT update folder" 200 "$STATUS"
    assert_json_field "updated folder name" "$BODY" ".name" "updated-folder"
}

test_ciphers() {
    section "Ciphers"

    # Create cipher (login type)
    local cipher_data='{"type":1,"name":"encrypted-name","login":{"username":"enc-user","password":"enc-pass","uri":"enc-uri"},"folderId":"'"$FOLDER_UUID"'","favorite":true}'
    parse_response "$(curl_post "/api/ciphers" "$cipher_data" "$ACCESS_TOKEN")"
    assert_status "POST create cipher" 200 "$STATUS"
    assert_json_field "cipher object" "$BODY" ".object" "cipherDetails"
    assert_json_exists "cipher has id" "$BODY" ".id"
    assert_json_field "cipher type" "$BODY" ".type" "1"
    assert_json_field "cipher is favorite" "$BODY" ".favorite" "true"
    assert_json_field "cipher folderId" "$BODY" ".folderId" "$FOLDER_UUID"
    CIPHER_UUID=$(echo "$BODY" | jq -r ".id")

    # Create a second cipher (card type)
    local cipher2='{"type":3,"name":"encrypted-card","card":{"cardholderName":"enc","number":"enc"}}'
    parse_response "$(curl_post "/api/ciphers" "$cipher2" "$ACCESS_TOKEN")"
    assert_status "POST create card cipher" 200 "$STATUS"
    local CIPHER2_UUID
    CIPHER2_UUID=$(echo "$BODY" | jq -r ".id")

    # Get cipher
    parse_response "$(curl_get "/api/ciphers/${CIPHER_UUID}" "$ACCESS_TOKEN")"
    assert_status "GET cipher" 200 "$STATUS"
    assert_json_field "cipher name" "$BODY" ".name" "encrypted-name"

    # Get cipher details (alternate endpoint)
    parse_response "$(curl_get "/api/ciphers/${CIPHER_UUID}/details" "$ACCESS_TOKEN")"
    assert_status "GET cipher details" 200 "$STATUS"

    # List ciphers
    parse_response "$(curl_get "/api/ciphers" "$ACCESS_TOKEN")"
    assert_status "GET ciphers list" 200 "$STATUS"
    TOTAL=$((TOTAL + 1))
    local count
    count=$(echo "$BODY" | jq '.data | length')
    if [ "$count" -ge 2 ]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} ciphers list has $count items"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}✗${NC} ciphers list has only $count items (expected >= 2)"
    fi

    # Update cipher
    local update_data='{"type":1,"name":"updated-name","login":{"username":"new-user","password":"new-pass"}}'
    parse_response "$(curl_put "/api/ciphers/${CIPHER_UUID}" "$update_data" "$ACCESS_TOKEN")"
    assert_status "PUT update cipher" 200 "$STATUS"
    assert_json_field "updated cipher name" "$BODY" ".name" "updated-name"

    # Soft delete (trash)
    parse_response "$(curl_put "/api/ciphers/${CIPHER2_UUID}/delete" '{}' "$ACCESS_TOKEN")"
    assert_status "PUT soft delete cipher" 200 "$STATUS"

    # Restore from trash
    parse_response "$(curl_put "/api/ciphers/${CIPHER2_UUID}/restore" '{}' "$ACCESS_TOKEN")"
    assert_status "PUT restore cipher" 200 "$STATUS"

    # Move ciphers to folder
    local move_data='{"ids":["'"$CIPHER_UUID"'"],"folderId":"'"$FOLDER_UUID"'"}'
    parse_response "$(curl_put "/api/ciphers/move" "$move_data" "$ACCESS_TOKEN")"
    assert_status "PUT move ciphers" 200 "$STATUS"

    # Delete cipher permanently
    parse_response "$(curl_delete "/api/ciphers/${CIPHER2_UUID}" "$ACCESS_TOKEN")"
    assert_status "DELETE cipher" 200 "$STATUS"
}

test_sync() {
    section "Sync"

    parse_response "$(curl_get "/api/sync" "$ACCESS_TOKEN")"
    assert_status "GET sync" 200 "$STATUS"
    assert_json_field "sync object" "$BODY" ".object" "sync"
    assert_json_exists "sync has profile" "$BODY" ".profile"
    assert_json_exists "sync has ciphers" "$BODY" ".ciphers"
    assert_json_exists "sync has folders" "$BODY" ".folders"
    assert_json_exists "sync has collections" "$BODY" ".collections"
    assert_json_exists "sync has sends" "$BODY" ".sends"
    assert_json_exists "sync has domains" "$BODY" ".domains"
    assert_json_field "sync is unofficial" "$BODY" ".unofficialServer" "true"
}

test_import() {
    section "Import"

    local import_data='{"ciphers":[{"type":1,"name":"imported-cipher","login":{"username":"u","password":"p"}},{"type":2,"name":"imported-note","secureNote":{"type":0}}],"folders":[{"name":"imported-folder"}],"folderRelationships":[{"key":0,"value":0}]}'
    parse_response "$(curl_post "/api/ciphers/import" "$import_data" "$ACCESS_TOKEN")"
    assert_status "POST import" 200 "$STATUS"

    # Verify import worked
    parse_response "$(curl_get "/api/ciphers" "$ACCESS_TOKEN")"
    TOTAL=$((TOTAL + 1))
    local count
    count=$(echo "$BODY" | jq '.data | length')
    if [ "$count" -ge 3 ]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} import created ciphers (total: $count)"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}✗${NC} import failed, only $count ciphers"
    fi
}

test_sends() {
    section "Sends"

    # Create text send
    local send_data='{"type":0,"name":"encrypted-send","key":"sendkey123","text":{"text":"encrypted-text","hidden":false},"deletionDate":"2030-01-01T00:00:00Z","maxAccessCount":5}'
    parse_response "$(curl_post "/api/sends" "$send_data" "$ACCESS_TOKEN")"
    assert_status "POST create send" 200 "$STATUS"
    assert_json_field "send object" "$BODY" ".object" "send"
    assert_json_exists "send has id" "$BODY" ".id"
    SEND_UUID=$(echo "$BODY" | jq -r ".id")

    # Get send
    parse_response "$(curl_get "/api/sends/${SEND_UUID}" "$ACCESS_TOKEN")"
    assert_status "GET send" 200 "$STATUS"
    assert_json_field "send name" "$BODY" ".name" "encrypted-send"

    # List sends
    parse_response "$(curl_get "/api/sends" "$ACCESS_TOKEN")"
    assert_status "GET sends list" 200 "$STATUS"
    assert_json_field "sends is list" "$BODY" ".object" "list"

    # Update send
    parse_response "$(curl_put "/api/sends/${SEND_UUID}" '{"name":"updated-send","key":"sendkey123","deletionDate":"2030-01-01T00:00:00Z"}' "$ACCESS_TOKEN")"
    assert_status "PUT update send" 200 "$STATUS"

    # Access send (public, no auth)
    parse_response "$(curl_post "/api/sends/access/${SEND_UUID}" '{}')"
    assert_status "POST access send" 200 "$STATUS"
    assert_json_exists "access has key" "$BODY" ".key"

    # Remove password
    parse_response "$(curl_put "/api/sends/${SEND_UUID}/remove-password" '{}' "$ACCESS_TOKEN")"
    assert_status "PUT remove send password" 200 "$STATUS"

    # Delete send
    parse_response "$(curl_delete "/api/sends/${SEND_UUID}" "$ACCESS_TOKEN")"
    assert_status "DELETE send" 200 "$STATUS"
}

test_organizations() {
    section "Organizations"

    # Create organization
    local org_data='{"name":"Test Org","billingEmail":"org@example.com","key":"orgkey123","keys":{"publicKey":"pubkey","encryptedPrivateKey":"privkey"}}'
    parse_response "$(curl_post "/api/organizations" "$org_data" "$ACCESS_TOKEN")"
    assert_status "POST create org" 200 "$STATUS"
    assert_json_exists "org has id" "$BODY" ".id"
    ORG_UUID=$(echo "$BODY" | jq -r ".id")

    # Get organization
    parse_response "$(curl_get "/api/organizations/${ORG_UUID}" "$ACCESS_TOKEN")"
    assert_status "GET org" 200 "$STATUS"
    assert_json_field "org name" "$BODY" ".name" "Test Org"

    # Get org keys
    parse_response "$(curl_get "/api/organizations/${ORG_UUID}/keys" "$ACCESS_TOKEN")"
    assert_status "GET org keys" 200 "$STATUS"
    assert_json_exists "org has publicKey" "$BODY" ".publicKey"

    # Get org members
    parse_response "$(curl_get "/api/organizations/${ORG_UUID}/users" "$ACCESS_TOKEN")"
    assert_status "GET org members" 200 "$STATUS"
    assert_json_field "members is list" "$BODY" ".object" "list"

    # Create collection
    parse_response "$(curl_post "/api/organizations/${ORG_UUID}/collections" '{"name":"Test Collection"}' "$ACCESS_TOKEN")"
    assert_status "POST create collection" 200 "$STATUS"
    assert_json_exists "collection has id" "$BODY" ".id"
    COLLECTION_UUID=$(echo "$BODY" | jq -r ".id")

    # Get collections
    parse_response "$(curl_get "/api/organizations/${ORG_UUID}/collections" "$ACCESS_TOKEN")"
    assert_status "GET org collections" 200 "$STATUS"

    # Get org policies
    parse_response "$(curl_get "/api/organizations/${ORG_UUID}/policies" "$ACCESS_TOKEN")"
    assert_status "GET org policies" 200 "$STATUS"

    # Delete collection
    parse_response "$(curl_delete "/api/organizations/${ORG_UUID}/collections/${COLLECTION_UUID}" "$ACCESS_TOKEN")"
    assert_status "DELETE collection" 200 "$STATUS"
}

test_twofactor() {
    section "Two-Factor Authentication"

    # Get 2FA providers (should be empty initially)
    parse_response "$(curl_get "/api/two-factor" "$ACCESS_TOKEN")"
    assert_status "GET two-factor" 200 "$STATUS"
    assert_json_field "2FA is list" "$BODY" ".object" "list"

    # Get authenticator (generates secret)
    parse_response "$(curl_post "/api/two-factor/get-authenticator" '{"masterPasswordHash":"hash123"}' "$ACCESS_TOKEN")"
    assert_status "POST get-authenticator" 200 "$STATUS"
    assert_json_exists "has key" "$BODY" ".key"
    assert_json_field "not enabled yet" "$BODY" ".enabled" "false"

    # Get email 2FA status
    parse_response "$(curl_post "/api/two-factor/get-email" '{"masterPasswordHash":"hash123"}' "$ACCESS_TOKEN")"
    assert_status "POST get-email" 200 "$STATUS"
    assert_json_field "email 2FA not enabled" "$BODY" ".enabled" "false"

    # Get device verification settings
    parse_response "$(curl_get "/api/two-factor/get-device-verification-settings")"
    assert_status "GET device-verification-settings" 200 "$STATUS"

    # Get recovery code
    parse_response "$(curl_post "/api/two-factor/get-recover" '{"masterPasswordHash":"hash123"}' "$ACCESS_TOKEN")"
    assert_status "POST get-recover" 200 "$STATUS"
}

test_emergency_access() {
    section "Emergency Access"

    # Get trusted contacts (empty initially)
    parse_response "$(curl_get "/api/emergency-access/trusted" "$ACCESS_TOKEN")"
    assert_status "GET trusted contacts" 200 "$STATUS"
    assert_json_field "trusted is list" "$BODY" ".object" "list"

    # Get granted access (empty initially)
    parse_response "$(curl_get "/api/emergency-access/granted" "$ACCESS_TOKEN")"
    assert_status "GET granted access" 200 "$STATUS"
    assert_json_field "granted is list" "$BODY" ".object" "list"

    # Invite emergency contact
    parse_response "$(curl_post "/api/emergency-access/invite" '{"email":"emergency@example.com","type":0,"waitTimeDays":7}' "$ACCESS_TOKEN")"
    assert_status "POST invite emergency contact" 200 "$STATUS"
}

test_eq_domains() {
    section "Equivalent Domains"

    parse_response "$(curl_get "/api/settings/domains" "$ACCESS_TOKEN")"
    assert_status "GET eq domains" 200 "$STATUS"
    assert_json_field "domains object" "$BODY" ".object" "domains"

    parse_response "$(curl_put "/api/settings/domains" '{"equivalentDomains":[["example.com","example.org"]],"excludedGlobalEquivalentDomains":[]}' "$ACCESS_TOKEN")"
    assert_status "PUT eq domains" 200 "$STATUS"
}

test_events() {
    section "Events"

    parse_response "$(curl_post "/api/collect" '[{"type":1000,"date":"2024-01-01T00:00:00Z"}]' "$ACCESS_TOKEN")"
    assert_status "POST collect events" 200 "$STATUS"
}

test_notifications() {
    section "Notifications"

    parse_response "$(curl_post "/notifications/hub/negotiate" '{}' "$ACCESS_TOKEN")"
    assert_status "POST negotiate" 200 "$STATUS"
    assert_json_exists "negotiate has connectionId" "$BODY" ".connectionId"
}

test_auth_errors() {
    section "Auth Error Handling"

    # No auth header
    parse_response "$(curl_get "/api/accounts/profile")"
    assert_status "GET profile without auth returns 401" 401 "$STATUS"

    # Invalid token
    parse_response "$(curl_get "/api/accounts/profile" "invalid-token-here")"
    assert_status "GET profile with bad token returns 401" 401 "$STATUS"

    # Unsupported grant type
    parse_response "$(curl_post "/identity/connect/token" "grant_type=magic" "" "application/x-www-form-urlencoded")"
    assert_status "unsupported grant_type returns 400" 400 "$STATUS"
}

test_misc_endpoints() {
    section "Misc Endpoints"

    parse_response "$(curl_get "/api/hibp/breach" "$ACCESS_TOKEN")"
    assert_status "GET HIBP breach" 200 "$STATUS"

    parse_response "$(curl_get "/api/ciphers/organization-details" "$ACCESS_TOKEN")"
    assert_status "GET org cipher details" 200 "$STATUS"
}

test_cleanup() {
    section "Cleanup (Delete)"

    # Delete folder
    parse_response "$(curl_delete "/api/folders/${FOLDER_UUID}" "$ACCESS_TOKEN")"
    assert_status "DELETE folder" 200 "$STATUS"

    # Delete remaining test ciphers via purge
    parse_response "$(curl_post "/api/ciphers/purge" '{"masterPasswordHash":"hash123"}' "$ACCESS_TOKEN")"
    assert_status "POST purge ciphers" 200 "$STATUS"

    # Verify purge worked
    parse_response "$(curl_get "/api/ciphers" "$ACCESS_TOKEN")"
    TOTAL=$((TOTAL + 1))
    local count
    count=$(echo "$BODY" | jq '.data | length')
    if [ "$count" -eq 0 ]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} purge removed all ciphers"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}✗${NC} purge left $count ciphers"
    fi

    # Delete org
    parse_response "$(curl_delete "/api/organizations/${ORG_UUID}" "$ACCESS_TOKEN" '{"masterPasswordHash":"hash123"}')"
    assert_status "DELETE organization" 200 "$STATUS"

    # Delete account
    parse_response "$(curl_post "/api/accounts/delete" '{"masterPasswordHash":"hash123"}' "$ACCESS_TOKEN")"
    assert_status "POST delete account" 200 "$STATUS"

    # Delete second test user
    local login2="grant_type=password&username=test2@example.com&password=hash456&client_id=web&scope=api&deviceIdentifier=d2&deviceName=Test&deviceType=7"
    parse_response "$(curl_post "/identity/connect/token" "$login2" "" "application/x-www-form-urlencoded")"
    local token2
    token2=$(echo "$BODY" | jq -r ".access_token")
    if [ "$token2" != "null" ] && [ -n "$token2" ]; then
        curl_post "/api/accounts/delete" '{"masterPasswordHash":"hash456"}' "$token2" >/dev/null 2>&1
    fi
}

# =============================================================================
# Run All Tests
# =============================================================================

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Vaultwarden CF Workers - End-to-End Test Suite           ║${NC}"
echo -e "${BLUE}║   Target: ${BASE_URL}                          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Clean up any previous test data
section "Setup"
echo "  Cleaning previous test data..."
curl -s -X POST "${BASE_URL}/identity/connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&username=test@example.com&password=hash123&client_id=web&scope=api&deviceIdentifier=d0&deviceName=Clean&deviceType=7" > /tmp/vw_clean_token.json 2>/dev/null
CLEAN_TOKEN=$(jq -r '.access_token // empty' /tmp/vw_clean_token.json 2>/dev/null)
if [ -n "$CLEAN_TOKEN" ]; then
    curl -s -X POST "${BASE_URL}/api/accounts/delete" -H "Authorization: Bearer $CLEAN_TOKEN" -H "Content-Type: application/json" -d '{"masterPasswordHash":"hash123"}' >/dev/null 2>&1
fi
curl -s -X POST "${BASE_URL}/identity/connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&username=test2@example.com&password=hash456&client_id=web&scope=api&deviceIdentifier=d0&deviceName=Clean&deviceType=7" > /tmp/vw_clean_token2.json 2>/dev/null
CLEAN_TOKEN2=$(jq -r '.access_token // empty' /tmp/vw_clean_token2.json 2>/dev/null)
if [ -n "$CLEAN_TOKEN2" ]; then
    curl -s -X POST "${BASE_URL}/api/accounts/delete" -H "Authorization: Bearer $CLEAN_TOKEN2" -H "Content-Type: application/json" -d '{"masterPasswordHash":"hash456"}' >/dev/null 2>&1
fi
echo "  Done."

test_health
test_cors
test_register
test_prelogin
test_login
test_refresh
test_profile
test_api_key
test_security_stamp
test_folders
test_ciphers
test_sync
test_import
test_sends
test_organizations
test_twofactor
test_emergency_access
test_eq_domains
test_events
test_notifications
test_auth_errors
test_misc_endpoints
test_cleanup

# =============================================================================
# Summary
# =============================================================================

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "  Total: ${TOTAL}  ${GREEN}Passed: ${PASS}${NC}  ${RED}Failed: ${FAIL}${NC}  ${YELLOW}Skipped: ${SKIP}${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

if [ "$FAIL" -gt 0 ]; then
    echo -e "\n${RED}Failures:${NC}${FAILURES}"
    echo ""
    exit 1
else
    echo -e "\n${GREEN}All tests passed!${NC}"
    echo ""
    exit 0
fi
