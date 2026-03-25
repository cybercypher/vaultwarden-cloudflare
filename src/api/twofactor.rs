use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha1::Sha1;
use worker::{Env, Request, Response};

use crate::auth;
use crate::crypto;
use crate::db;
use crate::error::{Error, Result};
use crate::models::User;
use crate::util;

const TOTP_TYPE: i32 = 0; // Authenticator = 0
const EMAIL_TYPE: i32 = 1; // Email = 1

// ============================================================================
// TOTP Implementation (RFC 6238)
// ============================================================================

fn generate_totp_secret() -> String {
    // Generate 20 bytes (160 bits) of randomness, encode as base32
    let bytes = crypto::get_random_bytes::<20>();
    base32_encode(&bytes)
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let idx = ((buffer >> bits_left) & 0x1f) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }

    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0x1f) as usize;
        result.push(ALPHABET[idx] as char);
    }

    result
}

fn base32_decode(data: &str) -> Option<Vec<u8>> {
    let data = data.to_uppercase().replace([' ', '-'], "");
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for ch in data.chars() {
        let val = match ch {
            'A'..='Z' => ch as u64 - 'A' as u64,
            '2'..='7' => ch as u64 - '2' as u64 + 26,
            '=' => continue,
            _ => return None,
        };
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            result.push((buffer >> bits_left) as u8);
        }
    }

    Some(result)
}

fn verify_totp(secret: &str, code: &str, time_step: u64) -> bool {
    // Allow 1 time step of drift in either direction
    let now = chrono::Utc::now().timestamp() as u64;
    for offset in [-1i64, 0, 1] {
        let adjusted_time = (now as i64 + offset * time_step as i64) as u64;
        let counter = adjusted_time / time_step;
        let counter_bytes = counter.to_be_bytes();

        if let Some(key_bytes) = base32_decode(secret) {
            if let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&key_bytes) {
                mac.update(&counter_bytes);
                let result = mac.finalize().into_bytes();

                let off = (result[19] & 0x0f) as usize;
                let otp_code = ((result[off] as u32 & 0x7f) << 24)
                    | ((result[off + 1] as u32) << 16)
                    | ((result[off + 2] as u32) << 8)
                    | (result[off + 3] as u32);

                let expected = format!("{:06}", otp_code % 1_000_000);
                if crate::crypto::ct_eq(&expected, code) {
                    return true;
                }
            }
        }
    }
    false
}

// ============================================================================
// 2FA API Endpoints
// ============================================================================

/// GET /api/two-factor
pub async fn get_twofactor(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct TF {
        uuid: String,
        atype: i32,
        enabled: i32,
    }

    let factors: Vec<TF> =
        db::query_all(&d1, "SELECT uuid, atype, enabled FROM twofactor WHERE user_uuid = ?1", &[db::val(&claims.sub)])
            .await?;

    let factor_list: Vec<Value> = factors
        .iter()
        .map(|f| {
            json!({
                "enabled": f.enabled != 0,
                "type": f.atype,
                "object": "twoFactorProvider",
            })
        })
        .collect();

    let response = json!({
        "data": factor_list,
        "object": "list",
        "continuationToken": Value::Null,
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/two-factor/get-authenticator
pub async fn get_authenticator(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    verify_password_from_body(&body, &claims.sub, &d1).await?;

    // Check if already has TOTP
    #[derive(serde::Deserialize)]
    struct TF {
        data: String,
        enabled: i32,
    }
    let existing: Option<TF> = db::query_one(
        &d1,
        "SELECT data, enabled FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &[db::val(&claims.sub), db::val_i32(TOTP_TYPE)],
    )
    .await?;

    let (key, enabled) = if let Some(tf) = existing {
        (tf.data, tf.enabled != 0)
    } else {
        (generate_totp_secret(), false)
    };

    let response = json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/two-factor/authenticator
pub async fn activate_authenticator(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    verify_password_from_body(&body, &claims.sub, &d1).await?;

    let key = body["key"].as_str().ok_or_else(|| Error::bad_request("key required"))?;
    let token = body["token"].as_str().ok_or_else(|| Error::bad_request("token required"))?;

    // Verify the TOTP token matches the key
    if !verify_totp(key, token, 30) {
        return Err(Error::bad_request("Invalid TOTP token. Make sure your authenticator app is set up correctly."));
    }

    // Generate recovery code
    let recover = crypto::get_random_string_alphanum(32);

    // Upsert twofactor record
    let tf_uuid = util::get_uuid();
    db::execute(
        &d1,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &[db::val(&claims.sub), db::val_i32(TOTP_TYPE)],
    )
    .await?;
    db::execute(
        &d1,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, 1, ?4, 0)",
        &[db::val(&tf_uuid), db::val(&claims.sub), db::val_i32(TOTP_TYPE), db::val(key)],
    )
    .await?;

    // Store recovery code on user
    db::execute(&d1, "UPDATE users SET totp_recover = ?1 WHERE uuid = ?2", &[db::val(&recover), db::val(&claims.sub)])
        .await?;

    let response = json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/two-factor/disable
pub async fn disable_twofactor(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    verify_password_from_body(&body, &claims.sub, &d1).await?;

    let tf_type = body["type"].as_i64().ok_or_else(|| Error::bad_request("type required"))? as i32;

    db::execute(
        &d1,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &[db::val(&claims.sub), db::val_i32(tf_type)],
    )
    .await?;

    let response = json!({
        "enabled": false,
        "type": tf_type,
        "object": "twoFactorProvider",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/two-factor/get-recover
pub async fn get_recover(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    verify_password_from_body(&body, &claims.sub, &d1).await?;

    let user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    let response = json!({
        "code": user.totp_recover,
        "object": "twoFactorRecover",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/two-factor/get-email
pub async fn get_email(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    verify_password_from_body(&body, &claims.sub, &d1).await?;

    #[derive(serde::Deserialize)]
    struct TF {
        data: String,
        enabled: i32,
    }
    let existing: Option<TF> = db::query_one(
        &d1,
        "SELECT data, enabled FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &[db::val(&claims.sub), db::val_i32(EMAIL_TYPE)],
    )
    .await?;

    let user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    let (email, enabled) = if let Some(tf) = existing {
        (tf.data, tf.enabled != 0)
    } else {
        (user.email.clone(), false)
    };

    let response = json!({
        "email": email,
        "enabled": enabled,
        "object": "twoFactorEmail",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// PUT /api/two-factor/email
pub async fn activate_email(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    verify_password_from_body(&body, &claims.sub, &d1).await?;

    let email = body["email"].as_str().ok_or_else(|| Error::bad_request("email required"))?;
    let token = body["token"].as_str().ok_or_else(|| Error::bad_request("token required"))?;

    // Verify the token against KV stored token
    let kv = env.kv("KV").map_err(|e| Error::internal(e.to_string()))?;
    let stored_token = kv
        .get(&format!("2fa_email_{}_{}", claims.sub, email))
        .text()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;

    if !stored_token.as_ref().map(|s| crate::crypto::ct_eq(s, token)).unwrap_or(false) {
        return Err(Error::bad_request("Invalid token"));
    }

    // Upsert email 2FA
    let tf_uuid = util::get_uuid();
    db::execute(
        &d1,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &[db::val(&claims.sub), db::val_i32(EMAIL_TYPE)],
    )
    .await?;
    db::execute(
        &d1,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, 1, ?4, 0)",
        &[db::val(&tf_uuid), db::val(&claims.sub), db::val_i32(EMAIL_TYPE), db::val(email)],
    )
    .await?;

    let response = json!({
        "email": email,
        "enabled": true,
        "object": "twoFactorEmail",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/two-factor/send-email-login
pub async fn send_email_login(mut req: Request, env: &Env) -> Result<Response> {
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let email = body["email"].as_str().ok_or_else(|| Error::bad_request("email required"))?;

    let user = User::find_by_email(email, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    // Check if email 2FA is enabled
    #[derive(serde::Deserialize)]
    struct TF {
        data: String,
    }
    let tf: Option<TF> = db::query_one(
        &d1,
        "SELECT data FROM twofactor WHERE user_uuid = ?1 AND atype = ?2 AND enabled = 1",
        &[db::val(&user.uuid), db::val_i32(EMAIL_TYPE)],
    )
    .await?;

    if let Some(tf) = tf {
        let token = crypto::get_random_string_alphanum(6).to_uppercase();

        // Store in KV with 15-minute expiration
        let kv = env.kv("KV").map_err(|e| Error::internal(e.to_string()))?;
        kv.put(&format!("2fa_email_{}_{}", user.uuid, tf.data), &token)
            .map_err(|e| Error::internal(e.to_string()))?
            .expiration_ttl(900)
            .execute()
            .await
            .map_err(|e| Error::internal(e.to_string()))?;

        // Send the token via email
        let _ = crate::mail::send_2fa_token(env, &tf.data, &token).await;
    }

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/two-factor/send-email
pub async fn send_email(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let email = body["email"].as_str().ok_or_else(|| Error::bad_request("email required"))?;

    let token = crypto::get_random_string_alphanum(6).to_uppercase();

    let kv = env.kv("KV").map_err(|e| Error::internal(e.to_string()))?;
    kv.put(&format!("2fa_email_{}_{}", claims.sub, email), &token)
        .map_err(|e| Error::internal(e.to_string()))?
        .expiration_ttl(900)
        .execute()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;

    let _ = crate::mail::send_2fa_token(env, email, &token).await;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/two-factor/get-device-verification-settings
pub fn get_device_verification_settings() -> Result<Response> {
    let response = json!({
        "isDeviceVerificationSectionEnabled": false,
        "unknownDeviceVerificationEnabled": false,
        "object": "deviceVerificationSettings",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

// ============================================================================
// 2FA Verification for Login Flow
// ============================================================================

/// Check if user has any 2FA enabled, and if so verify the provided token.
/// Returns Ok(true) if 2FA is not required or verification passed.
/// Returns Err if 2FA is required but token is missing/invalid.
pub async fn verify_2fa(
    user_uuid: &str,
    two_factor_token: Option<&str>,
    two_factor_provider: Option<i32>,
    two_factor_remember: Option<&str>,
    d1: &worker::D1Database,
    env: &Env,
) -> Result<bool> {
    // Check if user has any 2FA enabled
    #[derive(serde::Deserialize)]
    struct TF {
        atype: i32,
        data: String,
    }
    let factors: Vec<TF> = db::query_all(
        d1,
        "SELECT atype, data FROM twofactor WHERE user_uuid = ?1 AND enabled = 1",
        &[db::val(user_uuid)],
    )
    .await?;

    if factors.is_empty() {
        return Ok(true); // No 2FA enabled
    }

    // Check remember token
    if let Some(remember) = two_factor_remember {
        if !remember.is_empty() {
            // Verify remember token JWT
            let domain = env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default();
            if auth::decode_jwt::<auth::TwoFactorRememberClaims>(remember, &format!("{domain}|2faremember"), env)
                .is_ok()
            {
                return Ok(true);
            }
        }
    }

    let token = two_factor_token.ok_or_else(|| {
        Error::new(
            json!({
                "error": "invalid_grant",
                "error_description": "Two factor required.",
                "TwoFactorProviders": factors.iter().map(|f| f.atype).collect::<Vec<_>>(),
                "TwoFactorProviders2": {},
                "MasterPasswordPolicy": {},
            })
            .to_string(),
            400,
        )
    })?;

    let provider = two_factor_provider.unwrap_or(0);

    match provider {
        0 => {
            // TOTP authenticator
            let totp_factor = factors.iter().find(|f| f.atype == TOTP_TYPE);
            if let Some(tf) = totp_factor {
                if verify_totp(&tf.data, token, 30) {
                    // Update last_used
                    let now = chrono::Utc::now().timestamp();
                    let _ = db::execute(
                        d1,
                        "UPDATE twofactor SET last_used = ?1 WHERE user_uuid = ?2 AND atype = ?3",
                        &[db::val_i64(now), db::val(user_uuid), db::val_i32(TOTP_TYPE)],
                    )
                    .await;
                    return Ok(true);
                }
            }
            Err(Error::bad_request("Invalid TOTP token"))
        }
        1 => {
            // Email
            let email_factor = factors.iter().find(|f| f.atype == EMAIL_TYPE);
            if let Some(tf) = email_factor {
                let kv = env.kv("KV").map_err(|e| Error::internal(e.to_string()))?;
                let stored = kv
                    .get(&format!("2fa_email_{}_{}", user_uuid, tf.data))
                    .text()
                    .await
                    .map_err(|e| Error::internal(e.to_string()))?;
                if stored.as_ref().map(|s| crate::crypto::ct_eq(s, token)).unwrap_or(false) {
                    // Delete used token
                    let _ = kv.delete(&format!("2fa_email_{}_{}", user_uuid, tf.data)).await;
                    return Ok(true);
                }
            }
            Err(Error::bad_request("Invalid email token"))
        }
        _ => Err(Error::bad_request("Unsupported 2FA provider")),
    }
}

// ============================================================================
// Helpers
// ============================================================================

async fn verify_password_from_body(body: &Value, user_uuid: &str, d1: &worker::D1Database) -> Result<()> {
    let hash = body["masterPasswordHash"].as_str().ok_or_else(|| Error::bad_request("masterPasswordHash required"))?;
    let user = User::find_by_uuid(user_uuid, d1).await?.ok_or_else(|| Error::not_found("User not found"))?;
    if !user.check_valid_password(hash) {
        return Err(Error::bad_request("Invalid password"));
    }
    Ok(())
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}
