use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use worker::{Env, Request, Response};

use crate::auth;
use crate::crypto;
use crate::db;
use crate::error::{Error, Result};
use crate::models::Send;
use crate::util;

/// GET /api/sends
pub async fn list(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let sends = Send::find_by_user(&claims.sub, &d1).await?;
    let send_list: Vec<Value> = sends.iter().map(|s| s.to_json()).collect();

    let response = json!({
        "data": send_list,
        "object": "list",
        "continuationToken": Value::Null,
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/sends/:id
pub async fn get(req: Request, env: &Env, send_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let send = Send::find_by_uuid(send_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Send not found"))?;

    if send.user_uuid.as_deref() != Some(&claims.sub) {
        return Err(Error::not_found("Send not found"));
    }

    Response::from_json(&send.to_json()).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/sends
pub async fn create(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let send = create_send_from_data(&claims.sub, &body, &d1).await?;

    Response::from_json(&send.to_json()).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/sends/file/v2
pub async fn create_file_v2(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let send = create_send_from_data(&claims.sub, &body, &d1).await?;

    // Generate a file upload URL (file ID for R2)
    let file_id = crypto::generate_id::<16>();

    let response = json!({
        "sendResponse": send.to_json(),
        "fileUploadType": 0, // Azure = 0, direct upload
        "url": format!("/api/sends/{}/file/{}", send.uuid, file_id),
        "object": "send-fileUpload",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/sends/:send_id/file/:file_id (upload file data for send)
pub async fn upload_file(mut req: Request, env: &Env, send_id: &str, file_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let send = Send::find_by_uuid(send_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Send not found"))?;

    if send.user_uuid.as_deref() != Some(&claims.sub) {
        return Err(Error::not_found("Send not found"));
    }

    // Store file in R2
    let r2 = env.bucket("ATTACHMENTS").map_err(|e| Error::internal(e.to_string()))?;
    let file_data = req.bytes().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let r2_key = format!("sends/{}/{}", send_id, file_id);

    r2.put(&r2_key, file_data)
        .execute()
        .await
        .map_err(|e| Error::internal(format!("R2 upload failed: {e}")))?;

    // Update send data with file info
    let mut data: Value = serde_json::from_str(&send.data).unwrap_or(json!({}));
    data["id"] = json!(file_id);
    data["size"] = json!(0); // Size not tracked precisely at upload
    data["sizeName"] = json!("unknown");

    db::execute(
        &d1,
        "UPDATE sends SET data = ?1, revision_date = ?2 WHERE uuid = ?3",
        &[db::val(&data.to_string()), db::val(&util::now_utc()), db::val(send_id)],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// PUT /api/sends/:id
pub async fn update(mut req: Request, env: &Env, send_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let mut send = Send::find_by_uuid(send_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Send not found"))?;

    if send.user_uuid.as_deref() != Some(&claims.sub) {
        return Err(Error::not_found("Send not found"));
    }

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    update_send_from_data(&mut send, &body)?;
    send.revision_date = util::now_utc();
    send.save(&d1).await?;

    Response::from_json(&send.to_json()).map_err(|e| Error::internal(e.to_string()))
}

/// DELETE /api/sends/:id
pub async fn delete(req: Request, env: &Env, send_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let send = Send::find_by_uuid(send_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Send not found"))?;

    if send.user_uuid.as_deref() != Some(&claims.sub) {
        return Err(Error::not_found("Send not found"));
    }

    // Delete R2 files if file type
    if send.atype == 1 {
        if let Ok(r2) = env.bucket("ATTACHMENTS") {
            let _ = r2.delete(&format!("sends/{}/", send_id)).await;
        }
    }

    Send::delete(send_id, &d1).await?;
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// PUT /api/sends/:id/remove-password
pub async fn remove_password(req: Request, env: &Env, send_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let mut send = Send::find_by_uuid(send_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Send not found"))?;

    if send.user_uuid.as_deref() != Some(&claims.sub) {
        return Err(Error::not_found("Send not found"));
    }

    send.password_hash = None;
    send.password_salt = None;
    send.password_iter = None;
    send.revision_date = util::now_utc();
    send.save(&d1).await?;

    Response::from_json(&send.to_json()).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/sends/access/:access_id - Public access to a send (no auth required)
pub async fn access(mut req: Request, env: &Env, access_id: &str) -> Result<Response> {
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let send = Send::find_by_uuid(access_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Send does not exist or is no longer available"))?;

    if send.disabled != 0 {
        return Err(Error::not_found("Send does not exist or is no longer available"));
    }

    // Check expiration
    if let Some(exp) = &send.expiration_date {
        if let Some(exp_dt) = util::parse_date(exp) {
            if exp_dt.and_utc() < chrono::Utc::now() {
                return Err(Error::not_found("Send does not exist or is no longer available"));
            }
        }
    }

    // Check deletion date
    if let Some(del_dt) = util::parse_date(&send.deletion_date) {
        if del_dt.and_utc() < chrono::Utc::now() {
            return Err(Error::not_found("Send does not exist or is no longer available"));
        }
    }

    // Check max access count
    if let Some(max) = send.max_access_count {
        if send.access_count >= max {
            return Err(Error::not_found("Send does not exist or is no longer available"));
        }
    }

    // Check password
    let body: Value = req.json().await.unwrap_or(json!({}));
    if send.password_hash.is_some() {
        let password = body["password"]
            .as_str()
            .ok_or_else(|| Error::bad_request("Password required for this Send"))?;

        if let (Some(hash), Some(salt), Some(iter)) =
            (&send.password_hash, &send.password_salt, send.password_iter)
        {
            let stored_hash = STANDARD.decode(hash).unwrap_or_default();
            let stored_salt = STANDARD.decode(salt).unwrap_or_default();
            if !crypto::verify_password_hash(
                password.as_bytes(),
                &stored_salt,
                &stored_hash,
                iter as u32,
            ) {
                return Err(Error::unauthorized("Invalid password"));
            }
        }
    }

    // Increment access count
    db::execute(
        &d1,
        "UPDATE sends SET access_count = access_count + 1 WHERE uuid = ?1",
        &[db::val(access_id)],
    ).await?;

    let data: Value = serde_json::from_str(&send.data).unwrap_or(Value::Null);
    let response = json!({
        "id": send.uuid,
        "type": send.atype,
        "name": send.name,
        "text": if send.atype == 0 { data.clone() } else { Value::Null },
        "file": if send.atype == 1 { data.clone() } else { Value::Null },
        "key": send.akey,
        "expirationDate": send.expiration_date.as_ref().map(|d| util::format_date(d)),
        "object": "send-access",
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/sends/:send_id/access/file/:file_id - Download a send file (no auth required)
pub async fn access_file(mut req: Request, env: &Env, send_id: &str, file_id: &str) -> Result<Response> {
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let send = Send::find_by_uuid(send_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Send does not exist or is no longer available"))?;

    if send.disabled != 0 || send.atype != 1 {
        return Err(Error::not_found("Send does not exist or is no longer available"));
    }

    // Check password
    let body: Value = req.json().await.unwrap_or(json!({}));
    if send.password_hash.is_some() {
        let password = body["password"]
            .as_str()
            .ok_or_else(|| Error::bad_request("Password required"))?;
        if let (Some(hash), Some(salt), Some(iter)) =
            (&send.password_hash, &send.password_salt, send.password_iter)
        {
            let stored_hash = STANDARD.decode(hash).unwrap_or_default();
            let stored_salt = STANDARD.decode(salt).unwrap_or_default();
            if !crypto::verify_password_hash(password.as_bytes(), &stored_salt, &stored_hash, iter as u32) {
                return Err(Error::unauthorized("Invalid password"));
            }
        }
    }

    let domain = get_domain(env);
    let response = json!({
        "id": file_id,
        "url": format!("{}/api/sends/{}/{}?t=send-access", domain, send_id, file_id),
        "object": "send-fileDownload",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/sends/:send_id/:file_id?t=<token> - Direct file download
/// Validates the send still exists, is not disabled/expired/over-limit before serving.
pub async fn download_file(req: Request, env: &Env, send_id: &str, file_id: &str) -> Result<Response> {
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    // Validate the send is still accessible
    let send = Send::find_by_uuid(send_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Send does not exist or is no longer available"))?;

    if send.disabled != 0 || send.atype != 1 {
        return Err(Error::not_found("Send does not exist or is no longer available"));
    }
    if let Some(exp) = &send.expiration_date {
        if let Some(exp_dt) = crate::util::parse_date(exp) {
            if exp_dt.and_utc() < chrono::Utc::now() {
                return Err(Error::not_found("Send has expired"));
            }
        }
    }
    if let Some(del_dt) = crate::util::parse_date(&send.deletion_date) {
        if del_dt.and_utc() < chrono::Utc::now() {
            return Err(Error::not_found("Send has been deleted"));
        }
    }
    if let Some(max) = send.max_access_count {
        if send.access_count > max {
            return Err(Error::not_found("Send access limit reached"));
        }
    }

    let r2 = env.bucket("ATTACHMENTS").map_err(|e| Error::internal(e.to_string()))?;
    let r2_key = format!("sends/{}/{}", send_id, file_id);

    let object = r2
        .get(&r2_key)
        .execute()
        .await
        .map_err(|e| Error::internal(format!("R2 error: {e}")))?
        .ok_or_else(|| Error::not_found("File not found"))?;

    let body = object.body().ok_or_else(|| Error::internal("Empty R2 object"))?;
    let bytes = body.bytes().await.map_err(|e| Error::internal(e.to_string()))?;

    let mut resp = Response::from_bytes(bytes).map_err(|e| Error::internal(e.to_string()))?;
    let _ = resp.headers_mut().set("Content-Type", "application/octet-stream");
    let _ = resp.headers_mut().set("Cache-Control", "no-cache, no-store, must-revalidate");
    Ok(resp)
}

// ============================================================================
// Helpers
// ============================================================================

async fn create_send_from_data(user_uuid: &str, data: &Value, d1: &worker::D1Database) -> Result<Send> {
    let atype = data["type"].as_i64().ok_or_else(|| Error::bad_request("type required"))? as i32;
    let name = data["name"].as_str().ok_or_else(|| Error::bad_request("name required"))?;
    let key = data["key"].as_str().ok_or_else(|| Error::bad_request("key required"))?;
    let deletion_date = data["deletionDate"]
        .as_str()
        .ok_or_else(|| Error::bad_request("deletionDate required"))?;

    let type_data = match atype {
        0 => data.get("text").map(|d| d.to_string()).unwrap_or_else(|| "{}".to_string()),
        1 => data.get("file").map(|d| d.to_string()).unwrap_or_else(|| "{}".to_string()),
        _ => return Err(Error::bad_request("Invalid send type")),
    };

    let now = util::now_utc();
    let mut send = Send {
        uuid: util::get_uuid(),
        user_uuid: Some(user_uuid.to_string()),
        organization_uuid: None,
        name: name.to_string(),
        notes: data["notes"].as_str().map(|s| s.to_string()),
        atype,
        data: type_data,
        akey: key.to_string(),
        password_hash: None,
        password_salt: None,
        password_iter: None,
        max_access_count: data["maxAccessCount"].as_i64().map(|n| n as i32),
        access_count: 0,
        creation_date: now.clone(),
        revision_date: now,
        expiration_date: data["expirationDate"].as_str().map(|s| s.to_string()),
        deletion_date: deletion_date.to_string(),
        disabled: if data["disabled"].as_bool().unwrap_or(false) { 1 } else { 0 },
        hide_email: data["hideEmail"].as_bool().map(|b| if b { 1 } else { 0 }),
    };

    // Set password if provided
    if let Some(pw) = data["password"].as_str() {
        if !pw.is_empty() {
            set_send_password(&mut send, pw);
        }
    }

    send.save(d1).await?;
    Ok(send)
}

fn update_send_from_data(send: &mut Send, data: &Value) -> Result<()> {
    if let Some(name) = data["name"].as_str() {
        send.name = name.to_string();
    }
    send.notes = data["notes"].as_str().map(|s| s.to_string());
    send.max_access_count = data["maxAccessCount"].as_i64().map(|n| n as i32);
    send.expiration_date = data["expirationDate"].as_str().map(|s| s.to_string());
    if let Some(del) = data["deletionDate"].as_str() {
        send.deletion_date = del.to_string();
    }
    send.disabled = if data["disabled"].as_bool().unwrap_or(false) { 1 } else { 0 };
    send.hide_email = data["hideEmail"].as_bool().map(|b| if b { 1 } else { 0 });

    if let Some(pw) = data["password"].as_str() {
        if !pw.is_empty() {
            set_send_password(send, pw);
        }
    }

    Ok(())
}

fn set_send_password(send: &mut Send, password: &str) {
    const PASSWORD_ITER: i32 = 100_000;
    let salt = crypto::get_random_bytes::<64>();
    let hash = crypto::hash_password(password.as_bytes(), &salt, PASSWORD_ITER as u32);
    send.password_hash = Some(STANDARD.encode(&hash));
    send.password_salt = Some(STANDARD.encode(&salt));
    send.password_iter = Some(PASSWORD_ITER);
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}
