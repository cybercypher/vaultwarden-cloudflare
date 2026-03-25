use serde_json::Value;
use worker::{Env, Request, Response};

use crate::auth;
use crate::error::{Error, Result};
use crate::models::User;

/// GET /api/accounts/profile
pub async fn profile(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    // Get organizations
    let memberships = crate::models::Membership::find_confirmed_by_user(&user.uuid, &d1).await?;
    let mut org_list = Vec::new();
    for m in &memberships {
        if let Some(org) = crate::models::Organization::find_by_uuid(&m.org_uuid, &d1).await? {
            org_list.push(org.to_json(m));
        }
    }

    let mut profile = user.to_json();
    profile["organizations"] = Value::Array(org_list);

    Response::from_json(&profile).map_err(|e| Error::internal(e.to_string()))
}

/// PUT /api/accounts/profile
pub async fn put_profile(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;

    let mut user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    if let Some(name) = body["name"].as_str() {
        user.name = name.to_string();
    }

    user.updated_at = crate::util::now_utc();
    user.save(&d1).await?;

    let profile = user.to_json();
    Response::from_json(&profile).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/accounts/keys
pub async fn post_keys(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;

    let mut user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    if let Some(public_key) = body["publicKey"].as_str() {
        user.public_key = Some(public_key.to_string());
    }
    if let Some(enc_priv_key) = body["encryptedPrivateKey"].as_str() {
        user.private_key = Some(enc_priv_key.to_string());
    }

    user.updated_at = crate::util::now_utc();
    user.save(&d1).await?;

    let profile = user.to_json();
    Response::from_json(&profile).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/accounts/revision-date
pub async fn revision_date(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    // Return as milliseconds timestamp
    let dt = crate::util::parse_date(&user.updated_at);
    let ms = dt.map(|d| d.and_utc().timestamp_millis()).unwrap_or(0);

    Response::ok(ms.to_string()).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/accounts/password-hint
pub async fn password_hint(mut req: Request, env: &Env) -> Result<Response> {
    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let email = body["email"].as_str().ok_or_else(|| Error::bad_request("email is required"))?;

    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    // Look up user and send hint if email is configured
    // Always return OK to not leak user existence
    if let Some(user) = User::find_by_email(email, &d1).await? {
        let _ = crate::mail::send_password_hint(env, email, user.password_hint.as_deref()).await;
    }

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/accounts/verify-password
pub async fn verify_password(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let master_password_hash =
        body["masterPasswordHash"].as_str().ok_or_else(|| Error::bad_request("masterPasswordHash is required"))?;

    let user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    if !user.check_valid_password(master_password_hash) {
        return Err(Error::bad_request("Invalid password"));
    }

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/accounts/kdf
pub async fn post_kdf(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;

    let mut user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    // Verify current password
    let master_password_hash =
        body["masterPasswordHash"].as_str().ok_or_else(|| Error::bad_request("masterPasswordHash is required"))?;
    if !user.check_valid_password(master_password_hash) {
        return Err(Error::bad_request("Invalid password"));
    }

    // Update KDF settings
    let new_master_password_hash = body["newMasterPasswordHash"]
        .as_str()
        .ok_or_else(|| Error::bad_request("newMasterPasswordHash is required"))?;
    let key = body["key"].as_str().ok_or_else(|| Error::bad_request("key is required"))?;

    let server_iterations: u32 =
        env.var("PASSWORD_ITERATIONS").map(|v| v.to_string().parse().unwrap_or(600000)).unwrap_or(600000);

    user.set_password(new_master_password_hash, user.password_hint.clone(), server_iterations);
    user.akey = key.to_string();

    if let Some(kdf) = body["kdf"].as_i64() {
        user.client_kdf_type = kdf as i32;
    }
    if let Some(iter) = body["kdfIterations"].as_i64() {
        user.client_kdf_iter = iter as i32;
    }
    user.client_kdf_memory = body["kdfMemory"].as_i64().map(|v| v as i32);
    user.client_kdf_parallelism = body["kdfParallelism"].as_i64().map(|v| v as i32);

    user.security_stamp = crate::util::get_uuid();
    user.updated_at = crate::util::now_utc();
    user.save(&d1).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/accounts/password
pub async fn post_password(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;

    let mut user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    let master_password_hash =
        body["masterPasswordHash"].as_str().ok_or_else(|| Error::bad_request("masterPasswordHash is required"))?;
    if !user.check_valid_password(master_password_hash) {
        return Err(Error::bad_request("Invalid password"));
    }

    let new_hash = body["newMasterPasswordHash"]
        .as_str()
        .ok_or_else(|| Error::bad_request("newMasterPasswordHash is required"))?;
    let key = body["key"].as_str().ok_or_else(|| Error::bad_request("key is required"))?;

    let server_iterations: u32 =
        env.var("PASSWORD_ITERATIONS").map(|v| v.to_string().parse().unwrap_or(600000)).unwrap_or(600000);

    let hint = body["masterPasswordHint"].as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    user.set_password(new_hash, hint, server_iterations);
    user.akey = key.to_string();
    user.security_stamp = crate::util::get_uuid();
    user.updated_at = crate::util::now_utc();
    user.save(&d1).await?;

    // Invalidate all devices except current (forces re-login)
    // The security stamp change will invalidate existing JWTs on validation

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/accounts/delete or DELETE /api/accounts
pub async fn delete_account(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.unwrap_or(serde_json::json!({}));
    let master_password_hash =
        body["masterPasswordHash"].as_str().ok_or_else(|| Error::bad_request("masterPasswordHash is required"))?;

    let user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    if !user.check_valid_password(master_password_hash) {
        return Err(Error::bad_request("Invalid password"));
    }

    User::delete(&claims.sub, &d1).await?;
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/accounts/security-stamp
pub async fn post_security_stamp(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let master_password_hash =
        body["masterPasswordHash"].as_str().ok_or_else(|| Error::bad_request("masterPasswordHash is required"))?;

    let mut user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    if !user.check_valid_password(master_password_hash) {
        return Err(Error::bad_request("Invalid password"));
    }

    user.security_stamp = crate::util::get_uuid();
    user.updated_at = crate::util::now_utc();
    user.save(&d1).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/accounts/api-key
pub async fn get_api_key(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let master_password_hash =
        body["masterPasswordHash"].as_str().ok_or_else(|| Error::bad_request("masterPasswordHash is required"))?;

    let mut user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    if !user.check_valid_password(master_password_hash) {
        return Err(Error::bad_request("Invalid password"));
    }

    // Generate API key if not exists
    if user.api_key.is_none() {
        user.api_key = Some(crate::crypto::generate_api_key());
        user.updated_at = crate::util::now_utc();
        user.save(&d1).await?;
    }

    let response = serde_json::json!({
        "apiKey": user.api_key,
        "object": "apiKey",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/accounts/rotate-api-key
pub async fn rotate_api_key(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let master_password_hash =
        body["masterPasswordHash"].as_str().ok_or_else(|| Error::bad_request("masterPasswordHash is required"))?;

    let mut user = User::find_by_uuid(&claims.sub, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    if !user.check_valid_password(master_password_hash) {
        return Err(Error::bad_request("Invalid password"));
    }

    user.api_key = Some(crate::crypto::generate_api_key());
    user.updated_at = crate::util::now_utc();
    user.save(&d1).await?;

    let response = serde_json::json!({
        "apiKey": user.api_key,
        "object": "apiKey",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/devices
pub async fn get_devices(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let devices = crate::models::Device::find_by_user(&claims.sub, &d1).await?;
    let device_list: Vec<Value> = devices.iter().map(|d| d.to_json()).collect();

    let response = serde_json::json!({
        "data": device_list,
        "object": "list",
        "continuationToken": Value::Null,
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/collections
pub async fn get_collections(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let collections = crate::models::Collection::find_by_user(&claims.sub, &d1).await?;
    let collection_list: Vec<Value> = collections.iter().map(|c| c.to_json()).collect();

    let response = serde_json::json!({
        "data": collection_list,
        "object": "list",
        "continuationToken": Value::Null,
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}
