use serde_json::{json, Value};
use worker::{Env, Request, Response};

use crate::auth;
use crate::db;
use crate::error::{Error, Result};
use crate::util;

const EA_INVITED: i32 = 0;
const EA_ACCEPTED: i32 = 1;
const EA_CONFIRMED: i32 = 2;
const EA_RECOVERY_INITIATED: i32 = 3;
const EA_RECOVERY_APPROVED: i32 = 4;

const EA_TYPE_TAKEOVER: i32 = 1;

#[derive(serde::Deserialize, Clone)]
#[allow(dead_code)]
struct EmergencyAccess {
    uuid: String,
    grantor_uuid: String,
    grantee_uuid: Option<String>,
    email: Option<String>,
    key_encrypted: Option<String>,
    atype: i32,
    status: i32,
    wait_time_days: i32,
    recovery_initiated_at: Option<String>,
    last_notification_at: Option<String>,
    updated_at: String,
    created_at: String,
}

fn ea_to_json(ea: &EmergencyAccess, grantor_name: &str, grantor_email: &str, grantee_name: &str, grantee_email: &str) -> Value {
    json!({
        "id": ea.uuid,
        "grantorId": ea.grantor_uuid,
        "granteeId": ea.grantee_uuid,
        "email": ea.email.as_deref().or(Some(grantee_email)).unwrap_or(""),
        "keyEncrypted": ea.key_encrypted,
        "type": ea.atype,
        "status": ea.status,
        "waitTimeDays": ea.wait_time_days,
        "creationDate": util::format_date(&ea.created_at),
        "revisionDate": util::format_date(&ea.updated_at),
        "object": "emergencyAccessGranteeDetails",
    })
}

/// GET /api/emergency-access/trusted (contacts I granted access to)
pub async fn get_contacts(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let eas: Vec<EmergencyAccess> = db::query_all(
        &d1, "SELECT * FROM emergency_access WHERE grantor_uuid = ?1", &[db::val(&claims.sub)],
    ).await?;

    let mut list = Vec::new();
    for ea in &eas {
        list.push(ea_to_json(ea, "", "", "", ea.email.as_deref().unwrap_or("")));
    }

    let response = json!({"data": list, "object": "list", "continuationToken": Value::Null});
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/emergency-access/granted (access granted to me)
pub async fn get_grantees(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let eas: Vec<EmergencyAccess> = db::query_all(
        &d1, "SELECT * FROM emergency_access WHERE grantee_uuid = ?1", &[db::val(&claims.sub)],
    ).await?;

    let mut list = Vec::new();
    for ea in &eas {
        let grantor = crate::models::User::find_by_uuid(&ea.grantor_uuid, &d1).await?;
        let name = grantor.as_ref().map(|u| u.name.as_str()).unwrap_or("");
        let email = grantor.as_ref().map(|u| u.email.as_str()).unwrap_or("");
        list.push(json!({
            "id": ea.uuid,
            "grantorId": ea.grantor_uuid,
            "granteeId": ea.grantee_uuid,
            "email": email,
            "name": name,
            "keyEncrypted": ea.key_encrypted,
            "type": ea.atype,
            "status": ea.status,
            "waitTimeDays": ea.wait_time_days,
            "creationDate": util::format_date(&ea.created_at),
            "revisionDate": util::format_date(&ea.updated_at),
            "object": "emergencyAccessGrantorDetails",
        }));
    }

    let response = json!({"data": list, "object": "list", "continuationToken": Value::Null});
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/emergency-access/invite
pub async fn invite(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let email = body["email"].as_str().ok_or_else(|| Error::bad_request("email required"))?.to_lowercase();
    let atype = body["type"].as_i64().ok_or_else(|| Error::bad_request("type required"))? as i32;
    let wait_time_days = body["waitTimeDays"].as_i64().ok_or_else(|| Error::bad_request("waitTimeDays required"))? as i32;

    let grantee = crate::models::User::find_by_email(&email, &d1).await?;
    let now = util::now_utc();
    let ea_uuid = util::get_uuid();

    db::execute(
        &d1,
        "INSERT INTO emergency_access (uuid, grantor_uuid, grantee_uuid, email, key_encrypted, atype, status, wait_time_days, updated_at, created_at)
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, ?8)",
        &[
            db::val(&ea_uuid), db::val(&claims.sub),
            db::val_opt(&grantee.as_ref().map(|u| u.uuid.clone())),
            db::val(&email), db::val_i32(atype),
            db::val_i32(EA_INVITED), db::val_i32(wait_time_days),
            db::val(&now),
        ],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/emergency-access/:id/accept
pub async fn accept(mut req: Request, env: &Env, ea_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    db::execute(
        &d1,
        "UPDATE emergency_access SET grantee_uuid = ?1, status = ?2, updated_at = ?3 WHERE uuid = ?4 AND status = ?5",
        &[db::val(&claims.sub), db::val_i32(EA_ACCEPTED), db::val(&util::now_utc()), db::val(ea_id), db::val_i32(EA_INVITED)],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/emergency-access/:id/confirm
pub async fn confirm(mut req: Request, env: &Env, ea_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let key = body["key"].as_str().ok_or_else(|| Error::bad_request("key required"))?;

    db::execute(
        &d1,
        "UPDATE emergency_access SET key_encrypted = ?1, status = ?2, updated_at = ?3 WHERE uuid = ?4 AND grantor_uuid = ?5 AND status = ?6",
        &[db::val(key), db::val_i32(EA_CONFIRMED), db::val(&util::now_utc()), db::val(ea_id), db::val(&claims.sub), db::val_i32(EA_ACCEPTED)],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/emergency-access/:id/initiate
pub async fn initiate(req: Request, env: &Env, ea_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let now = util::now_utc();
    db::execute(
        &d1,
        "UPDATE emergency_access SET status = ?1, recovery_initiated_at = ?2, updated_at = ?2 WHERE uuid = ?3 AND grantee_uuid = ?4 AND status = ?5",
        &[db::val_i32(EA_RECOVERY_INITIATED), db::val(&now), db::val(ea_id), db::val(&claims.sub), db::val_i32(EA_CONFIRMED)],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/emergency-access/:id/approve
pub async fn approve(req: Request, env: &Env, ea_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    db::execute(
        &d1,
        "UPDATE emergency_access SET status = ?1, updated_at = ?2 WHERE uuid = ?3 AND grantor_uuid = ?4 AND status = ?5",
        &[db::val_i32(EA_RECOVERY_APPROVED), db::val(&util::now_utc()), db::val(ea_id), db::val(&claims.sub), db::val_i32(EA_RECOVERY_INITIATED)],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/emergency-access/:id/reject
pub async fn reject(req: Request, env: &Env, ea_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    db::execute(
        &d1,
        "UPDATE emergency_access SET status = ?1, updated_at = ?2 WHERE uuid = ?3 AND grantor_uuid = ?4 AND status = ?5",
        &[db::val_i32(EA_CONFIRMED), db::val(&util::now_utc()), db::val(ea_id), db::val(&claims.sub), db::val_i32(EA_RECOVERY_INITIATED)],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/emergency-access/:id/view
pub async fn view(req: Request, env: &Env, ea_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let ea: EmergencyAccess = db::query_one(
        &d1, "SELECT * FROM emergency_access WHERE uuid = ?1 AND grantee_uuid = ?2 AND status = ?3",
        &[db::val(ea_id), db::val(&claims.sub), db::val_i32(EA_RECOVERY_APPROVED)],
    ).await?.ok_or_else(|| Error::not_found("Emergency access not found or not approved"))?;

    // Return grantor's ciphers
    let ciphers = crate::models::Cipher::find_by_user(&ea.grantor_uuid, &d1).await?;
    let cipher_list: Vec<Value> = ciphers.iter().map(|c| c.to_json(None, false, &[])).collect();

    let response = json!({
        "ciphers": cipher_list,
        "keyEncrypted": ea.key_encrypted,
        "object": "emergencyAccessView",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/emergency-access/:id/takeover
pub async fn takeover(req: Request, env: &Env, ea_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let ea: EmergencyAccess = db::query_one(
        &d1, "SELECT * FROM emergency_access WHERE uuid = ?1 AND grantee_uuid = ?2 AND status = ?3 AND atype = ?4",
        &[db::val(ea_id), db::val(&claims.sub), db::val_i32(EA_RECOVERY_APPROVED), db::val_i32(EA_TYPE_TAKEOVER)],
    ).await?.ok_or_else(|| Error::not_found("Emergency access not found or not approved for takeover"))?;

    let grantor = crate::models::User::find_by_uuid(&ea.grantor_uuid, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Grantor not found"))?;

    let response = json!({
        "keyEncrypted": ea.key_encrypted,
        "kdf": grantor.client_kdf_type,
        "kdfIterations": grantor.client_kdf_iter,
        "kdfMemory": grantor.client_kdf_memory,
        "kdfParallelism": grantor.client_kdf_parallelism,
        "object": "emergencyAccessTakeover",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// DELETE /api/emergency-access/:id
pub async fn delete_ea(req: Request, env: &Env, ea_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    db::execute(
        &d1,
        "DELETE FROM emergency_access WHERE uuid = ?1 AND (grantor_uuid = ?2 OR grantee_uuid = ?2)",
        &[db::val(ea_id), db::val(&claims.sub)],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/emergency-access/:id/policies
pub async fn policies(_req: Request, _env: &Env, _ea_id: &str) -> Result<Response> {
    let response = json!({"data": [], "object": "list", "continuationToken": Value::Null});
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}
