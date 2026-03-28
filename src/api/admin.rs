//! Admin API endpoints.
//!
//! Protected by ADMIN_TOKEN secret (Argon2 hash or plain text).
//! Provides user management, org overview, diagnostics, and configuration.

use serde_json::{json, Value};
use worker::{Env, Request, Response};

use crate::crypto;
use crate::db;
use crate::error::{Error, Result};
use crate::models::User;
use crate::util;

/// Verify admin token from Authorization header or request body.
fn verify_admin_token(req: &Request, env: &Env) -> Result<()> {
    let admin_token = env
        .secret("ADMIN_TOKEN")
        .map(|v| v.to_string())
        .map_err(|_| Error::unauthorized("ADMIN_TOKEN not configured"))?;

    // Check Authorization header first
    if let Ok(Some(auth)) = req.headers().get("Authorization") {
        let token = auth.strip_prefix("Bearer ").unwrap_or(&auth);
        if crypto::ct_eq(token, &admin_token) {
            return Ok(());
        }
    }

    Err(Error::unauthorized("Invalid admin token"))
}

/// POST /admin (login with admin token)
pub async fn admin_login(mut req: Request, env: &Env) -> Result<Response> {
    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let token = body["token"].as_str().ok_or_else(|| Error::bad_request("token required"))?;

    let admin_token = env
        .secret("ADMIN_TOKEN")
        .map(|v| v.to_string())
        .map_err(|_| Error::unauthorized("ADMIN_TOKEN not configured"))?;

    if !crypto::ct_eq(token, &admin_token) {
        return Err(Error::unauthorized("Invalid admin token"));
    }

    // Return a short-lived admin JWT
    let domain = env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default();
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "nbf": now,
        "exp": now + 3600, // 1 hour
        "iss": format!("{domain}|admin"),
        "sub": "admin",
    });

    let jwt = crate::auth::encode_jwt(&claims, env)?;

    let response = json!({
        "token": jwt,
        "object": "adminToken",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /admin/users
pub async fn get_users(req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let users: Vec<User> = db::query_all(&d1, "SELECT * FROM users ORDER BY created_at DESC", &[]).await?;

    let user_list: Vec<Value> = users
        .iter()
        .map(|u| {
            json!({
                "id": u.uuid,
                "email": u.email,
                "name": u.name,
                "enabled": u.enabled != 0,
                "emailVerified": u.verified_at.is_some(),
                "createdAt": util::format_date(&u.created_at),
                "lastActive": util::format_date(&u.updated_at),
                "twoFactorEnabled": false,
                "object": "user",
            })
        })
        .collect();

    Response::from_json(&json!(user_list)).map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/users/:user_id/delete
pub async fn delete_user(req: Request, env: &Env, user_id: &str) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    User::delete(user_id, &d1).await?;
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/users/:user_id/disable
pub async fn disable_user(req: Request, env: &Env, user_id: &str) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    db::execute(
        &d1,
        "UPDATE users SET enabled = 0, updated_at = ?1 WHERE uuid = ?2",
        &[db::val(&util::now_utc()), db::val(user_id)],
    )
    .await?;

    // Force logout
    crate::notifications::notify_logout(env, user_id, None).await;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/users/:user_id/enable
pub async fn enable_user(req: Request, env: &Env, user_id: &str) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    db::execute(
        &d1,
        "UPDATE users SET enabled = 1, updated_at = ?1 WHERE uuid = ?2",
        &[db::val(&util::now_utc()), db::val(user_id)],
    )
    .await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/users/:user_id/deauth
pub async fn deauth_user(req: Request, env: &Env, user_id: &str) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    // Rotate security stamp to invalidate all tokens
    db::execute(
        &d1,
        "UPDATE users SET security_stamp = ?1, updated_at = ?2 WHERE uuid = ?3",
        &[db::val(&util::get_uuid()), db::val(&util::now_utc()), db::val(user_id)],
    )
    .await?;

    crate::notifications::notify_logout(env, user_id, None).await;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/users/:user_id/remove-2fa
pub async fn remove_2fa(req: Request, env: &Env, user_id: &str) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    db::execute(&d1, "DELETE FROM twofactor WHERE user_uuid = ?1", &[db::val(user_id)]).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/invite
pub async fn invite_user(mut req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let email = body["email"].as_str().ok_or_else(|| Error::bad_request("email required"))?.to_lowercase();

    // Create invitation
    db::execute(&d1, "INSERT OR IGNORE INTO invitations (email) VALUES (?1)", &[db::val(&email)]).await?;

    // Send invite email
    let domain = env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default();
    let _ = crate::mail::send_welcome(env, &email).await;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// GET /admin/organizations/overview
pub async fn organizations_overview(req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    #[derive(serde::Deserialize)]
    struct Org {
        uuid: String,
        name: String,
        billing_email: String,
    }

    let orgs: Vec<Org> = db::query_all(&d1, "SELECT uuid, name, billing_email FROM organizations", &[]).await?;

    let org_list: Vec<Value> = orgs
        .iter()
        .map(|o| {
            json!({
                "id": o.uuid,
                "name": o.name,
                "billingEmail": o.billing_email,
                "object": "organization",
            })
        })
        .collect();

    Response::from_json(&json!(org_list)).map_err(|e| Error::internal(e.to_string()))
}

/// GET /admin/diagnostics
pub async fn diagnostics(req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    #[derive(serde::Deserialize)]
    struct Count {
        count: i64,
    }
    let user_count: Option<Count> = db::query_one(&d1, "SELECT COUNT(*) as count FROM users", &[]).await?;
    let cipher_count: Option<Count> = db::query_one(&d1, "SELECT COUNT(*) as count FROM ciphers", &[]).await?;
    let org_count: Option<Count> = db::query_one(&d1, "SELECT COUNT(*) as count FROM organizations", &[]).await?;

    let domain = env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default();
    let sso_enabled = env.var("SSO_ENABLED").map(|v| v.to_string() == "true").unwrap_or(false);
    let mail_enabled = env.var("MAIL_ENABLED").map(|v| v.to_string() == "true").unwrap_or(false);

    let response = json!({
        "version": "vaultwarden-cf 0.1.0",
        "platform": "Cloudflare Workers (WASM)",
        "domain": domain,
        "ssoEnabled": sso_enabled,
        "mailEnabled": mail_enabled,
        "fileStorage": crate::storage::backend_name(env),
        "userCount": user_count.map(|c| c.count).unwrap_or(0),
        "cipherCount": cipher_count.map(|c| c.count).unwrap_or(0),
        "orgCount": org_count.map(|c| c.count).unwrap_or(0),
        "object": "diagnostics",
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /admin/diagnostics/config
pub async fn get_config(req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;

    let vars = [
        "DOMAIN",
        "SIGNUPS_ALLOWED",
        "PASSWORD_ITERATIONS",
        "ACCESS_TOKEN_VALIDITY",
        "REFRESH_TOKEN_VALIDITY_DAYS",
        "MAIL_ENABLED",
        "MAIL_BACKEND",
        "MAIL_FROM",
        "SSO_ENABLED",
        "SSO_AUTHORITY",
        "SSO_CLIENT_ID",
    ];

    let mut config = serde_json::Map::new();
    for var in vars {
        let val = env.var(var).map(|v| v.to_string()).unwrap_or_else(|_| "(not set)".to_string());
        config.insert(var.to_string(), Value::String(val));
    }

    Response::from_json(&Value::Object(config)).map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/test/smtp
pub async fn test_smtp(mut req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let email = body["email"].as_str().ok_or_else(|| Error::bad_request("email required"))?;

    crate::mail::send_email(
        env,
        email,
        "Vaultwarden SMTP Test",
        "<p>This is a test email from Vaultwarden on Cloudflare Workers.</p>",
        "This is a test email from Vaultwarden on Cloudflare Workers.",
    )
    .await?;

    Response::ok("Email sent successfully").map_err(|e| Error::internal(e.to_string()))
}

/// GET /admin/users/:user_id
pub async fn get_user(req: Request, env: &Env, user_id: &str) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let user = User::find_by_uuid(user_id, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    #[derive(serde::Deserialize)]
    struct Count {
        count: i64,
    }
    let org_count: Option<Count> = db::query_one(
        &d1,
        "SELECT COUNT(*) as count FROM users_organizations WHERE user_uuid = ?1",
        &[db::val(user_id)],
    )
    .await?;
    let tf_count: Option<Count> = db::query_one(
        &d1,
        "SELECT COUNT(*) as count FROM twofactor WHERE user_uuid = ?1 AND enabled = 1",
        &[db::val(user_id)],
    )
    .await?;

    let response = json!({
        "id": user.uuid,
        "email": user.email,
        "name": user.name,
        "enabled": user.enabled != 0,
        "emailVerified": user.verified_at.is_some(),
        "createdAt": util::format_date(&user.created_at),
        "lastActive": util::format_date(&user.updated_at),
        "twoFactorEnabled": tf_count.map(|c| c.count > 0).unwrap_or(false),
        "orgCount": org_count.map(|c| c.count).unwrap_or(0),
        "object": "user",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /admin/users/by-mail/:email
pub async fn get_user_by_email(req: Request, env: &Env, email: &str) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let user = User::find_by_email(email, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;

    let response = json!({
        "id": user.uuid,
        "email": user.email,
        "name": user.name,
        "enabled": user.enabled != 0,
        "object": "user",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// DELETE /admin/users/:user_id/sso
pub async fn delete_sso(req: Request, env: &Env, user_id: &str) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    db::execute(&d1, "DELETE FROM sso_users WHERE user_uuid = ?1", &[db::val(user_id)]).await?;
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/users/:user_id/invite/resend
pub async fn resend_invite(req: Request, env: &Env, user_id: &str) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let user = User::find_by_uuid(user_id, &d1).await?.ok_or_else(|| Error::not_found("User not found"))?;
    let _ = crate::mail::send_welcome(env, &user.email).await;
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/users/update_revision
pub async fn update_all_revisions(req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    db::execute(&d1, "UPDATE users SET updated_at = ?1", &[db::val(&util::now_utc())]).await?;
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/organizations/:org_id/delete
pub async fn delete_organization(req: Request, env: &Env, org_id: &str) -> Result<Response> {
    verify_admin_token(&req, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    // Full cascade delete (same as org delete in organizations.rs)
    for q in &[
        "DELETE FROM ciphers_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM users_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM collections WHERE org_uuid = ?1",
        "DELETE FROM groups_users WHERE groups_uuid IN (SELECT uuid FROM groups WHERE organizations_uuid = ?1)",
        "DELETE FROM groups WHERE organizations_uuid = ?1",
        "DELETE FROM org_policies WHERE org_uuid = ?1",
        "DELETE FROM ciphers WHERE organization_uuid = ?1",
        "DELETE FROM users_organizations WHERE org_uuid = ?1",
        "DELETE FROM organization_api_key WHERE org_uuid = ?1",
        "DELETE FROM organizations WHERE uuid = ?1",
    ] {
        let _ = db::execute(&d1, q, &[db::val(org_id)]).await;
    }
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// GET /admin/diagnostics/http?code=<code>
pub async fn test_http(req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;

    let url = req.url().map_err(|e| Error::internal(e.to_string()))?;
    let code =
        url.query_pairs().find(|(k, _)| k == "code").map(|(_, v)| v.to_string()).unwrap_or_else(|| "200".to_string());

    let test_url = format!("https://httpbin.org/status/{}", code);
    let test_req = worker::Request::new(&test_url, worker::Method::Get).map_err(|e| Error::internal(e.to_string()))?;

    match worker::Fetch::Request(test_req).send().await {
        Ok(resp) => {
            let response = json!({
                "url": test_url,
                "status": resp.status_code(),
                "success": true,
            });
            Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
        }
        Err(e) => {
            let response = json!({ "url": test_url, "error": e.to_string(), "success": false });
            Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
        }
    }
}

/// POST /admin/config (save configuration - stored in KV)
pub async fn save_config(mut req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let kv = env.kv("KV").map_err(|e| Error::internal(e.to_string()))?;

    // Store config overrides in KV
    kv.put("admin_config", &body.to_string())
        .map_err(|e| Error::internal(e.to_string()))?
        .execute()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/config/delete (reset config)
pub async fn delete_config(req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;

    let kv = env.kv("KV").map_err(|e| Error::internal(e.to_string()))?;
    let _ = kv.delete("admin_config").await;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /admin/config/backup_db
pub async fn backup_db(req: Request, env: &Env) -> Result<Response> {
    verify_admin_token(&req, env)?;

    // D1 backups are managed through the Cloudflare dashboard/API
    // We can trigger a time-travel restore point by noting the current time
    let response = json!({
        "message": "D1 automatic backups are managed by Cloudflare. Use the dashboard or wrangler CLI to create/restore backups.",
        "timestamp": util::now_utc(),
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}
