//! SSO/OIDC authentication support.
//!
//! Implements the OpenID Connect Authorization Code flow for Bitwarden clients.
//! Uses `fetch()` to communicate with the OIDC provider - no external crates needed.
//!
//! Configuration (wrangler.toml vars or secrets):
//!   SSO_ENABLED = "true"
//!   SSO_CLIENT_ID = "vaultwarden"
//!   SSO_CLIENT_SECRET = "..." (via `wrangler secret put SSO_CLIENT_SECRET`)
//!   SSO_AUTHORITY = "https://auth.example.com/realms/master" (OIDC issuer URL)

use base64::Engine;
use serde_json::{json, Value};
use wasm_bindgen::JsValue;
use worker::{Env, Request, Response};

use crate::auth;
use crate::db;
use crate::error::{Error, Result};
use crate::models::{Device, User};
use crate::util;

fn sso_enabled(env: &Env) -> bool {
    env.var("SSO_ENABLED").map(|v| v.to_string() == "true").unwrap_or(false)
}

fn get_authority(env: &Env) -> Result<String> {
    env.var("SSO_AUTHORITY").map(|v| v.to_string()).map_err(|_| Error::internal("SSO_AUTHORITY not configured"))
}

fn get_client_id(env: &Env) -> Result<String> {
    env.var("SSO_CLIENT_ID").map(|v| v.to_string()).map_err(|_| Error::internal("SSO_CLIENT_ID not configured"))
}

fn get_client_secret(env: &Env) -> Result<String> {
    env.secret("SSO_CLIENT_SECRET")
        .map(|v| v.to_string())
        .map_err(|_| Error::internal("SSO_CLIENT_SECRET not configured"))
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default()
}

/// Fetch the OIDC discovery document (.well-known/openid-configuration)
async fn discover_oidc(authority: &str) -> Result<Value> {
    let discovery_url = format!("{}/.well-known/openid-configuration", authority.trim_end_matches('/'));

    let req = worker::Request::new(&discovery_url, worker::Method::Get)
        .map_err(|e| Error::internal(format!("Discovery request error: {e}")))?;

    let mut resp =
        worker::Fetch::Request(req).send().await.map_err(|e| Error::internal(format!("Discovery fetch error: {e}")))?;

    if resp.status_code() != 200 {
        return Err(Error::internal(format!("OIDC discovery failed with status {}", resp.status_code())));
    }

    resp.json::<Value>().await.map_err(|e| Error::internal(format!("Discovery parse error: {e}")))
}

/// GET /identity/connect/authorize - Redirect to OIDC provider
pub async fn authorize(req: Request, env: &Env) -> Result<Response> {
    if !sso_enabled(env) {
        return Err(Error::bad_request("SSO is not enabled"));
    }

    let url = req.url().map_err(|e| Error::internal(e.to_string()))?;
    let domain = get_domain(env);
    let authority = get_authority(env)?;
    let client_id = get_client_id(env)?;

    let discovery = discover_oidc(&authority).await?;
    let authorization_endpoint = discovery["authorization_endpoint"]
        .as_str()
        .ok_or_else(|| Error::internal("Missing authorization_endpoint in OIDC discovery"))?;

    // Extract client parameters
    let redirect_uri = format!("{}/identity/connect/oidc-signin", domain);
    let state =
        url.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.to_string()).unwrap_or_else(|| util::get_uuid());
    let code_challenge = url.query_pairs().find(|(k, _)| k == "code_challenge").map(|(_, v)| v.to_string());
    let code_challenge_method =
        url.query_pairs().find(|(k, _)| k == "code_challenge_method").map(|(_, v)| v.to_string());

    // Store state in KV for verification on callback
    if let Ok(kv) = env.kv("KV") {
        let state_data = json!({
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        });
        let _ = kv
            .put(&format!("sso_state_{}", state), &state_data.to_string())
            .map_err(|e| Error::internal(e.to_string()))?
            .expiration_ttl(600) // 10 minute expiry
            .execute()
            .await;
    }

    // Build authorization URL
    let mut auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid+email+profile&state={}",
        authorization_endpoint,
        urlencoding(&client_id),
        urlencoding(&redirect_uri),
        urlencoding(&state),
    );

    if let Some(cc) = &code_challenge {
        auth_url.push_str(&format!("&code_challenge={}", urlencoding(cc)));
        if let Some(ccm) = &code_challenge_method {
            auth_url.push_str(&format!("&code_challenge_method={}", urlencoding(ccm)));
        }
    }

    // Redirect the user to the OIDC provider
    let mut headers = worker::Headers::new();
    headers.set("Location", &auth_url).map_err(|e| Error::internal(e.to_string()))?;

    Ok(Response::empty()?.with_status(302).with_headers(headers))
}

/// GET /identity/connect/oidc-signin?code=...&state=... - OIDC callback
pub async fn oidc_signin(req: Request, env: &Env) -> Result<Response> {
    if !sso_enabled(env) {
        return Err(Error::bad_request("SSO is not enabled"));
    }

    let url = req.url().map_err(|e| Error::internal(e.to_string()))?;

    // Check for error response
    let error = url.query_pairs().find(|(k, _)| k == "error").map(|(_, v)| v.to_string());
    if let Some(err) = error {
        let desc =
            url.query_pairs().find(|(k, _)| k == "error_description").map(|(_, v)| v.to_string()).unwrap_or_default();
        return Err(Error::bad_request(format!("SSO error: {err} - {desc}")));
    }

    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| Error::bad_request("Missing authorization code"))?;
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| Error::bad_request("Missing state parameter"))?;

    let domain = get_domain(env);
    let authority = get_authority(env)?;
    let client_id = get_client_id(env)?;
    let client_secret = get_client_secret(env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    // Verify state from KV
    if let Ok(kv) = env.kv("KV") {
        let stored =
            kv.get(&format!("sso_state_{}", state)).text().await.map_err(|e| Error::internal(e.to_string()))?;
        if stored.is_none() {
            return Err(Error::bad_request("Invalid or expired state"));
        }
        let _ = kv.delete(&format!("sso_state_{}", state)).await;
    }

    // Exchange code for tokens
    let discovery = discover_oidc(&authority).await?;
    let token_endpoint =
        discovery["token_endpoint"].as_str().ok_or_else(|| Error::internal("Missing token_endpoint"))?;

    let redirect_uri = format!("{}/identity/connect/oidc-signin", domain);
    let token_body = serde_urlencoded::to_string(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", &redirect_uri),
        ("client_id", &client_id),
        ("client_secret", &client_secret),
    ])
    .map_err(|e| Error::internal(format!("URL encode error: {e}")))?;

    let mut headers = worker::Headers::new();
    headers.set("Content-Type", "application/x-www-form-urlencoded").map_err(|e| Error::internal(e.to_string()))?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_headers(headers);
    init.with_body(Some(JsValue::from_str(&token_body)));

    let token_req = worker::Request::new_with_init(token_endpoint, &init)
        .map_err(|e| Error::internal(format!("Token request error: {e}")))?;

    let mut token_resp = worker::Fetch::Request(token_req)
        .send()
        .await
        .map_err(|e| Error::internal(format!("Token fetch error: {e}")))?;

    if token_resp.status_code() != 200 {
        let err_body = token_resp.text().await.unwrap_or_default();
        return Err(Error::internal(format!("Token exchange failed: {}", err_body)));
    }

    let token_data: Value = token_resp.json().await.map_err(|e| Error::internal(format!("Token parse error: {e}")))?;

    let id_token = token_data["id_token"].as_str().ok_or_else(|| Error::internal("Missing id_token"))?;

    // Decode ID token claims (without verification - the token endpoint already verified it)
    let id_parts: Vec<&str> = id_token.split('.').collect();
    if id_parts.len() != 3 {
        return Err(Error::internal("Invalid id_token format"));
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(id_parts[1])
        .map_err(|_| Error::internal("Invalid id_token payload encoding"))?;
    let id_claims: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| Error::internal("Invalid id_token payload"))?;

    let email =
        id_claims["email"].as_str().ok_or_else(|| Error::internal("id_token missing email claim"))?.to_lowercase();
    let sso_sub = id_claims["sub"].as_str().ok_or_else(|| Error::internal("id_token missing sub claim"))?;

    // Find or create user
    let mut user = if let Some(existing) = User::find_by_email(&email, &d1).await? {
        existing
    } else {
        // Auto-create user from SSO
        let mut new_user = User::new(email.clone());
        new_user.name =
            id_claims["name"].as_str().or(id_claims["preferred_username"].as_str()).unwrap_or(&email).to_string();
        new_user.verified_at = Some(util::now_utc());
        new_user.save(&d1).await?;
        new_user
    };

    // Store SSO identifier mapping
    db::execute(
        &d1,
        "INSERT OR REPLACE INTO sso_users (user_uuid, identifier) VALUES (?1, ?2)",
        &[db::val(&user.uuid), db::val(sso_sub)],
    )
    .await?;

    // Create device and tokens (same as password login)
    let device_id = util::get_uuid();
    let mut device = Device::new(device_id, user.uuid.clone(), "SSO Login".to_string(), 14);
    device.save(&d1).await?;

    let scope = vec!["api".to_string(), "offline_access".to_string()];
    let access_validity: i64 =
        env.var("ACCESS_TOKEN_VALIDITY").map(|v| v.to_string().parse().unwrap_or(7200)).unwrap_or(7200);
    let refresh_validity_days: i64 =
        env.var("REFRESH_TOKEN_VALIDITY_DAYS").map(|v| v.to_string().parse().unwrap_or(30)).unwrap_or(30);

    let access_claims = auth::make_login_claims(
        &user.uuid,
        &user.email,
        &user.name,
        &device.uuid,
        &Device::type_to_string(device.atype),
        &user.security_stamp,
        "web",
        scope.clone(),
        access_validity,
        &domain,
    );
    let refresh_claims = auth::make_refresh_claims(
        &user.uuid,
        &device.uuid,
        &device.refresh_token,
        scope,
        refresh_validity_days,
        &domain,
    );

    let access_token = auth::encode_jwt(&access_claims, env)?;
    let refresh_token = auth::encode_jwt(&refresh_claims, env)?;

    // Redirect back to web vault with tokens
    let redirect_url = format!(
        "{}/#/sso?code={}&state={}&access_token={}&refresh_token={}",
        domain, code, state, access_token, refresh_token
    );

    let mut resp_headers = worker::Headers::new();
    resp_headers.set("Location", &redirect_url).map_err(|e| Error::internal(e.to_string()))?;
    Ok(Response::empty()?.with_status(302).with_headers(resp_headers))
}

/// GET /identity/sso/prevalidate - Check SSO configuration
pub async fn prevalidate(req: Request, env: &Env) -> Result<Response> {
    if !sso_enabled(env) {
        return Err(Error::bad_request("SSO is not enabled"));
    }

    let authority = get_authority(env)?;
    let _ = discover_oidc(&authority).await?;

    let response = json!({
        "token": util::get_uuid(),
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// Handle the authorization_code grant type in the login flow
pub async fn sso_login(
    code: &str,
    code_verifier: Option<&str>,
    device_identifier: &str,
    device_name: &str,
    device_type: i32,
    d1: &worker::D1Database,
    env: &Env,
    domain: &str,
) -> Result<Response> {
    if !sso_enabled(env) {
        return Err(Error::bad_request("SSO is not enabled"));
    }

    let authority = get_authority(env)?;
    let client_id = get_client_id(env)?;
    let client_secret = get_client_secret(env)?;
    let discovery = discover_oidc(&authority).await?;
    let token_endpoint =
        discovery["token_endpoint"].as_str().ok_or_else(|| Error::internal("Missing token_endpoint"))?;

    let redirect_uri = format!("{}/identity/connect/oidc-signin", domain);
    let mut params = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), code.to_string()),
        ("redirect_uri".to_string(), redirect_uri),
        ("client_id".to_string(), client_id),
        ("client_secret".to_string(), client_secret),
    ];
    if let Some(cv) = code_verifier {
        params.push(("code_verifier".to_string(), cv.to_string()));
    }

    let token_body =
        serde_urlencoded::to_string(&params).map_err(|e| Error::internal(format!("URL encode error: {e}")))?;

    let mut headers = worker::Headers::new();
    headers.set("Content-Type", "application/x-www-form-urlencoded").map_err(|e| Error::internal(e.to_string()))?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_headers(headers);
    init.with_body(Some(JsValue::from_str(&token_body)));

    let token_req = worker::Request::new_with_init(token_endpoint, &init)
        .map_err(|e| Error::internal(format!("Token request error: {e}")))?;

    let mut token_resp = worker::Fetch::Request(token_req)
        .send()
        .await
        .map_err(|e| Error::internal(format!("Token fetch error: {e}")))?;

    if token_resp.status_code() != 200 {
        let err_body = token_resp.text().await.unwrap_or_default();
        return Err(Error::bad_request(format!("SSO token exchange failed: {}", err_body)));
    }

    let token_data: Value = token_resp.json().await.map_err(|e| Error::internal(format!("Token parse error: {e}")))?;

    // Decode id_token to get user info
    let id_token = token_data["id_token"].as_str().ok_or_else(|| Error::internal("Missing id_token"))?;
    let id_parts: Vec<&str> = id_token.split('.').collect();
    if id_parts.len() != 3 {
        return Err(Error::internal("Invalid id_token"));
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(id_parts[1])
        .map_err(|_| Error::internal("Invalid id_token encoding"))?;
    let id_claims: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| Error::internal("Invalid id_token payload"))?;

    let email = id_claims["email"].as_str().ok_or_else(|| Error::internal("id_token missing email"))?.to_lowercase();

    // Find or create user
    let user = if let Some(existing) = User::find_by_email(&email, d1).await? {
        existing
    } else {
        let mut new_user = User::new(email.clone());
        new_user.name = id_claims["name"].as_str().unwrap_or(&email).to_string();
        new_user.verified_at = Some(util::now_utc());
        new_user.save(d1).await?;
        new_user
    };

    // Device
    let mut device = match Device::find_by_uuid_and_user(device_identifier, &user.uuid, d1).await? {
        Some(d) => d,
        None => Device::new(device_identifier.to_string(), user.uuid.clone(), device_name.to_string(), device_type),
    };
    device.refresh_token = data_encoding::BASE64URL.encode(&crate::crypto::get_random_bytes::<64>());
    device.save(d1).await?;

    let scope = vec!["api".to_string(), "offline_access".to_string()];
    let access_validity: i64 =
        env.var("ACCESS_TOKEN_VALIDITY").map(|v| v.to_string().parse().unwrap_or(7200)).unwrap_or(7200);
    let refresh_validity_days: i64 =
        env.var("REFRESH_TOKEN_VALIDITY_DAYS").map(|v| v.to_string().parse().unwrap_or(30)).unwrap_or(30);

    let access_claims = auth::make_login_claims(
        &user.uuid,
        &user.email,
        &user.name,
        &device.uuid,
        &Device::type_to_string(device.atype),
        &user.security_stamp,
        "web",
        scope.clone(),
        access_validity,
        domain,
    );
    let refresh_claims = auth::make_refresh_claims(
        &user.uuid,
        &device.uuid,
        &device.refresh_token,
        scope,
        refresh_validity_days,
        domain,
    );

    let access_token = auth::encode_jwt(&access_claims, env)?;
    let refresh_token = auth::encode_jwt(&refresh_claims, env)?;

    let response = json!({
        "access_token": access_token,
        "expires_in": access_validity,
        "token_type": "Bearer",
        "refresh_token": refresh_token,
        "Key": user.akey,
        "PrivateKey": user.private_key,
        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ForcePasswordReset": false,
        "ResetMasterPassword": false,
        "scope": "api offline_access",
        "unofficialServer": true,
        "UserDecryptionOptions": {
            "hasMasterPassword": !user.password_hash.is_empty(),
            "object": "userDecryptionOptions"
        }
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}
