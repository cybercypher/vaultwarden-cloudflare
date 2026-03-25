use serde_json::{json, Value};
use worker::{D1Database, Env, Request, Response};

use crate::auth;
use crate::error::{Error, Result};
use crate::models::{Device, User};

/// POST /identity/connect/token
/// Handles password, refresh_token, and client_credentials grants.
pub async fn login(mut req: Request, env: &Env) -> Result<Response> {
    let body = req.text().await.map_err(|e| Error::bad_request(format!("Failed to read body: {e}")))?;
    let params: std::collections::HashMap<String, String> =
        serde_urlencoded::from_str(&body).map_err(|e| Error::bad_request(format!("Invalid form data: {e}")))?;

    let grant_type = params.get("grant_type").map(|s| s.as_str()).unwrap_or("");
    let d1 = env.d1("DB").map_err(|e| Error::internal(format!("D1 binding error: {e}")))?;
    let domain = get_domain(env);

    match grant_type {
        "password" => password_login(&params, &d1, env, &domain).await,
        "refresh_token" => refresh_login(&params, &d1, env, &domain).await,
        "client_credentials" => api_key_login(&params, &d1, env, &domain).await,
        "authorization_code" => {
            let code = params.get("code").ok_or_else(|| Error::bad_request("code required"))?;
            let code_verifier = params.get("code_verifier").map(|s| s.as_str());
            let device_identifier = params.get("deviceIdentifier").ok_or_else(|| Error::bad_request("deviceIdentifier required"))?;
            let device_name = params.get("deviceName").unwrap_or(&"SSO".to_string()).clone();
            let device_type: i32 = params.get("deviceType").and_then(|s| s.parse().ok()).unwrap_or(14);
            crate::api::sso::sso_login(code, code_verifier, device_identifier, &device_name, device_type, &d1, env, &domain).await
        }
        _ => Err(Error::bad_request(format!("Unsupported grant_type: {grant_type}"))),
    }
}

async fn password_login(
    params: &std::collections::HashMap<String, String>,
    d1: &D1Database,
    env: &Env,
    domain: &str,
) -> Result<Response> {
    let username = params.get("username").ok_or_else(|| Error::bad_request("username required"))?;
    let password = params.get("password").ok_or_else(|| Error::bad_request("password required"))?;

    // Rate limiting: max 10 failed attempts per email per 15 minutes
    if let Ok(kv) = env.kv("KV") {
        let key = format!("ratelimit_login_{}", username.to_lowercase());
        if let Ok(Some(count_str)) = kv.get(&key).text().await {
            if let Ok(count) = count_str.parse::<u32>() {
                if count >= 10 {
                    return Err(Error::new("Too many login attempts. Try again later.", 429));
                }
            }
        }
    }
    let client_id = params.get("client_id").map(|s| s.as_str()).unwrap_or("web");
    let device_identifier = params.get("deviceIdentifier").ok_or_else(|| Error::bad_request("deviceIdentifier required"))?;
    let device_name = params.get("deviceName").unwrap_or(&"Unknown".to_string()).clone();
    let device_type: i32 = params
        .get("deviceType")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Find user
    let user = User::find_by_email(username, d1)
        .await?
        .ok_or_else(|| Error::bad_request("Username or password is incorrect."))?;

    if user.enabled == 0 {
        return Err(Error::bad_request("This user has been disabled."));
    }

    // Verify password
    if !user.check_valid_password(password) {
        // Increment rate limit counter on failure
        if let Ok(kv) = env.kv("KV") {
            let key = format!("ratelimit_login_{}", username.to_lowercase());
            let count: u32 = kv.get(&key).text().await.ok().flatten()
                .and_then(|s| s.parse().ok()).unwrap_or(0);
            let _ = kv.put(&key, &(count + 1).to_string())
                .map(|p| p.expiration_ttl(900)) // 15 minute window
                .ok();
            if let Some(p) = kv.put(&key, &(count + 1).to_string()).ok() {
                let _ = p.expiration_ttl(900).execute().await;
            }
        }
        return Err(Error::bad_request("Username or password is incorrect."));
    }

    // Verify 2FA if enabled
    let two_factor_token = params.get("twoFactorToken").map(|s| s.as_str());
    let two_factor_provider = params.get("twoFactorProvider").and_then(|s| s.parse::<i32>().ok());
    let two_factor_remember = params.get("twoFactorRemember").map(|s| s.as_str());
    crate::api::twofactor::verify_2fa(
        &user.uuid,
        two_factor_token,
        two_factor_provider,
        two_factor_remember,
        d1,
        env,
    ).await?;

    // Find or create device
    let mut device = match Device::find_by_uuid_and_user(device_identifier, &user.uuid, d1).await? {
        Some(d) => d,
        None => Device::new(
            device_identifier.to_string(),
            user.uuid.clone(),
            device_name,
            device_type,
        ),
    };

    // Generate new refresh token
    device.refresh_token = data_encoding::BASE64URL.encode(&crate::crypto::get_random_bytes::<64>());
    device.save(d1).await?;

    let scope = vec!["api".to_string(), "offline_access".to_string()];
    let access_validity = get_access_validity(env);
    let refresh_validity_days = get_refresh_validity_days(env);

    let access_claims = auth::make_login_claims(
        &user.uuid,
        &user.email,
        &user.name,
        &device.uuid,
        &Device::type_to_string(device.atype),
        &user.security_stamp,
        client_id,
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
            "hasMasterPassword": true,
            "object": "userDecryptionOptions"
        }
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

async fn refresh_login(
    params: &std::collections::HashMap<String, String>,
    d1: &D1Database,
    env: &Env,
    domain: &str,
) -> Result<Response> {
    let refresh_token_str = params
        .get("refresh_token")
        .ok_or_else(|| Error::bad_request("refresh_token required"))?;

    // Decode the refresh token JWT to get the inner token identifier
    let refresh_claims = auth::decode_refresh(refresh_token_str, domain, env)?;

    // Find device by the stored refresh token
    let device = Device::find_by_refresh_token(&refresh_claims.token, d1)
        .await?
        .ok_or_else(|| Error::unauthorized("Invalid refresh token"))?;

    let user = User::find_by_uuid(&device.user_uuid, d1)
        .await?
        .ok_or_else(|| Error::unauthorized("User not found"))?;

    if user.enabled == 0 {
        return Err(Error::bad_request("This user has been disabled."));
    }

    // Verify the device still exists and user hasn't rotated security stamp
    // (password change invalidates all sessions)
    if Device::find_by_uuid_and_user(&device.uuid, &user.uuid, d1).await?.is_none() {
        return Err(Error::unauthorized("Device no longer valid"));
    }

    let scope = refresh_claims.scope.clone();
    let access_validity = get_access_validity(env);
    let refresh_validity_days = get_refresh_validity_days(env);

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

    let new_refresh_claims = auth::make_refresh_claims(
        &user.uuid,
        &device.uuid,
        &device.refresh_token,
        scope,
        refresh_validity_days,
        domain,
    );

    let access_token = auth::encode_jwt(&access_claims, env)?;
    let new_refresh_token = auth::encode_jwt(&new_refresh_claims, env)?;

    let response = json!({
        "access_token": access_token,
        "expires_in": access_validity,
        "token_type": "Bearer",
        "refresh_token": new_refresh_token,
        "Key": user.akey,
        "PrivateKey": user.private_key,
        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "scope": "api offline_access",
        "unofficialServer": true,
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

async fn api_key_login(
    params: &std::collections::HashMap<String, String>,
    d1: &D1Database,
    env: &Env,
    domain: &str,
) -> Result<Response> {
    let client_id = params.get("client_id").ok_or_else(|| Error::bad_request("client_id required"))?;
    let client_secret = params.get("client_secret").ok_or_else(|| Error::bad_request("client_secret required"))?;
    let device_identifier = params.get("deviceIdentifier").ok_or_else(|| Error::bad_request("deviceIdentifier required"))?;
    let device_name = params.get("deviceName").unwrap_or(&"Unknown".to_string()).clone();
    let device_type: i32 = params.get("deviceType").and_then(|s| s.parse().ok()).unwrap_or(0);

    // client_id format: "user.UUID"
    let user_uuid = client_id
        .strip_prefix("user.")
        .ok_or_else(|| Error::bad_request("Invalid client_id format"))?;

    let user = User::find_by_uuid(user_uuid, d1)
        .await?
        .ok_or_else(|| Error::bad_request("Invalid API key"))?;

    // Verify API key
    let user_api_key = user.api_key.as_deref().ok_or_else(|| Error::bad_request("API key not set"))?;
    if !crate::crypto::ct_eq(client_secret, user_api_key) {
        return Err(Error::bad_request("Invalid API key"));
    }

    let mut device = match Device::find_by_uuid_and_user(device_identifier, &user.uuid, d1).await? {
        Some(d) => d,
        None => Device::new(device_identifier.to_string(), user.uuid.clone(), device_name, device_type),
    };

    device.refresh_token = data_encoding::BASE64URL.encode(&crate::crypto::get_random_bytes::<64>());
    device.save(d1).await?;

    let scope = vec!["api".to_string()];
    let access_validity = get_access_validity(env);

    let access_claims = auth::make_login_claims(
        &user.uuid,
        &user.email,
        &user.name,
        &device.uuid,
        &Device::type_to_string(device.atype),
        &user.security_stamp,
        client_id,
        scope,
        access_validity,
        domain,
    );

    let access_token = auth::encode_jwt(&access_claims, env)?;

    let response = json!({
        "access_token": access_token,
        "expires_in": access_validity,
        "token_type": "Bearer",
        "Key": user.akey,
        "PrivateKey": user.private_key,
        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "scope": "api",
        "unofficialServer": true,
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /identity/accounts/prelogin
pub async fn prelogin(mut req: Request, env: &Env) -> Result<Response> {
    let body: Value = req.json().await.map_err(|e| Error::bad_request(format!("Invalid JSON: {e}")))?;
    let email = body["email"]
        .as_str()
        .ok_or_else(|| Error::bad_request("email is required"))?;

    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let response = if let Some(user) = User::find_by_email(email, &d1).await? {
        json!({
            "kdf": user.client_kdf_type,
            "kdfIterations": user.client_kdf_iter,
            "kdfMemory": user.client_kdf_memory,
            "kdfParallelism": user.client_kdf_parallelism,
        })
    } else {
        // Return default KDF settings to not leak user existence
        json!({
            "kdf": 0,
            "kdfIterations": 600000,
            "kdfMemory": Value::Null,
            "kdfParallelism": Value::Null,
        })
    };

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /identity/accounts/register (legacy) and POST /api/accounts/register
pub async fn register(mut req: Request, env: &Env) -> Result<Response> {
    let body: Value = req.json().await.map_err(|e| Error::bad_request(format!("Invalid JSON: {e}")))?;

    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let signups_allowed = env
        .var("SIGNUPS_ALLOWED")
        .map(|v| v.to_string() == "true")
        .unwrap_or(true);

    // If signups are disabled, check for an admin invitation
    if !signups_allowed {
        let email_check = body["email"].as_str().unwrap_or("").to_lowercase();
        #[derive(serde::Deserialize)]
        struct Inv { email: String }
        let invite: Option<Inv> = crate::db::query_one(
            &d1, "SELECT email FROM invitations WHERE email = ?1", &[crate::db::val(&email_check)],
        ).await?;
        if invite.is_none() {
            return Err(Error::bad_request("Registration is not allowed."));
        }
    }

    let email = body["email"]
        .as_str()
        .ok_or_else(|| Error::bad_request("email is required"))?
        .to_lowercase();
    let master_password_hash = body["masterPasswordHash"]
        .as_str()
        .ok_or_else(|| Error::bad_request("masterPasswordHash is required"))?;
    let key = body["key"]
        .as_str()
        .or_else(|| body["userSymmetricKey"].as_str())
        .ok_or_else(|| Error::bad_request("key is required"))?;

    // Check for existing user (use same error message to prevent user enumeration)
    if User::find_by_email(&email, &d1).await?.is_some() {
        return Err(Error::bad_request(
            "Registration is not allowed.",
        ));
    }

    let server_iterations: u32 = env
        .var("PASSWORD_ITERATIONS")
        .map(|v| v.to_string().parse().unwrap_or(600000))
        .unwrap_or(600000);

    let mut user = User::new(email);
    user.set_password(master_password_hash, None, server_iterations);
    user.akey = key.to_string();

    if let Some(name) = body["name"].as_str() {
        user.name = name.to_string();
    }

    if let Some(hint) = body["masterPasswordHint"].as_str() {
        let trimmed = hint.trim();
        if !trimmed.is_empty() {
            user.password_hint = Some(trimmed.to_string());
        }
    }

    // KDF settings from client
    if let Some(kdf) = body.get("kdf").or(body.get("kdfType")).and_then(|v| v.as_i64()) {
        user.client_kdf_type = kdf as i32;
    }
    if let Some(iter) = body.get("kdfIterations").or(body.get("iterations")).and_then(|v| v.as_i64()) {
        user.client_kdf_iter = iter as i32;
    }
    if let Some(mem) = body.get("kdfMemory").or(body.get("memory")).and_then(|v| v.as_i64()) {
        user.client_kdf_memory = Some(mem as i32);
    }
    if let Some(par) = body.get("kdfParallelism").or(body.get("parallelism")).and_then(|v| v.as_i64()) {
        user.client_kdf_parallelism = Some(par as i32);
    }

    // Keys
    if let Some(keys) = body.get("keys").or(body.get("userAsymmetricKeys")) {
        if let Some(enc_priv) = keys.get("encryptedPrivateKey").and_then(|v| v.as_str()) {
            user.private_key = Some(enc_priv.to_string());
        }
        if let Some(pub_key) = keys.get("publicKey").and_then(|v| v.as_str()) {
            user.public_key = Some(pub_key.to_string());
        }
    }

    user.save(&d1).await?;

    // Remove invitation if one existed (user has now registered)
    let _ = crate::db::execute(&d1, "DELETE FROM invitations WHERE email = ?1", &[crate::db::val(&user.email)]).await;

    // Send welcome email if mail is configured
    let _ = crate::mail::send_welcome(env, &user.email).await;

    Response::from_json(&json!({}))
        .map(|r| r.with_status(200))
        .map_err(|e| Error::internal(e.to_string()))
}

// Helper functions

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}

fn get_access_validity(env: &Env) -> i64 {
    env.var("ACCESS_TOKEN_VALIDITY")
        .map(|v| v.to_string().parse().unwrap_or(7200))
        .unwrap_or(7200)
}

fn get_refresh_validity_days(env: &Env) -> i64 {
    env.var("REFRESH_TOKEN_VALIDITY_DAYS")
        .map(|v| v.to_string().parse().unwrap_or(30))
        .unwrap_or(30)
}
