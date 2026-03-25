use serde_json::{json, Value};
use worker::{Env, Request, Response};

use crate::auth;
use crate::crypto;
use crate::db;
use crate::error::{Error, Result};
use crate::models::cipher::Cipher;
use crate::util;

/// POST /api/ciphers/:cipher_id/attachment/v2
pub async fn create_v2(mut req: Request, env: &Env, cipher_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let cipher = Cipher::find_by_uuid(cipher_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Cipher not found"))?;

    if !cipher.is_accessible_to_user(&claims.sub, &d1).await? {
        return Err(Error::not_found("Cipher not found"));
    }

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let file_name = body["fileName"].as_str().unwrap_or("attachment");
    let file_size = body["fileSize"].as_i64().unwrap_or(0);
    let key = body["key"].as_str();

    let att_id = crypto::generate_id::<10>();

    // Create attachment record
    db::execute(
        &d1,
        "INSERT INTO attachments (id, cipher_uuid, file_name, file_size, akey) VALUES (?1, ?2, ?3, ?4, ?5)",
        &[
            db::val(&att_id),
            db::val(cipher_id),
            db::val(file_name),
            db::val_i64(file_size),
            db::val_opt(&key.map(|s| s.to_string())),
        ],
    ).await?;

    // Update cipher revision
    db::execute(
        &d1,
        "UPDATE ciphers SET updated_at = ?1 WHERE uuid = ?2",
        &[db::val(&util::now_utc()), db::val(cipher_id)],
    ).await?;

    let att_json = json!({
        "id": att_id,
        "url": format!("{}/api/ciphers/{}/attachment/{}", domain, cipher_id, att_id),
        "fileName": file_name,
        "size": file_size,
        "sizeName": format_size(file_size),
        "key": key,
        "object": "attachment",
    });

    let response = json!({
        "cipherResponse": cipher.to_json(None, false, &[att_json.clone()]),
        "cipherMiniResponse": cipher.to_json(None, false, &[att_json.clone()]),
        "fileUploadType": 0,
        "url": format!("{}/api/ciphers/{}/attachment/{}", domain, cipher_id, att_id),
        "object": "attachment-fileUpload",
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/ciphers/:cipher_id/attachment/:att_id (upload file data)
pub async fn upload(mut req: Request, env: &Env, cipher_id: &str, att_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let cipher = Cipher::find_by_uuid(cipher_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Cipher not found"))?;

    if !cipher.is_accessible_to_user(&claims.sub, &d1).await? {
        return Err(Error::not_found("Cipher not found"));
    }

    // Store file in R2
    let r2 = env.bucket("ATTACHMENTS").map_err(|e| Error::internal(e.to_string()))?;
    let file_data = req.bytes().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let file_size = file_data.len() as i64;
    let r2_key = format!("attachments/{}/{}", cipher_id, att_id);

    r2.put(&r2_key, file_data)
        .execute()
        .await
        .map_err(|e| Error::internal(format!("R2 upload failed: {e}")))?;

    // Update file size
    db::execute(
        &d1,
        "UPDATE attachments SET file_size = ?1 WHERE id = ?2",
        &[db::val_i64(file_size), db::val(att_id)],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/ciphers/:cipher_id/attachment/:att_id
pub async fn get(req: Request, env: &Env, cipher_id: &str, att_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let cipher = Cipher::find_by_uuid(cipher_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Cipher not found"))?;

    if !cipher.is_accessible_to_user(&claims.sub, &d1).await? {
        return Err(Error::not_found("Cipher not found"));
    }

    #[derive(serde::Deserialize)]
    struct Att { id: String, file_name: String, file_size: i64, akey: Option<String> }
    let att: Option<Att> = db::query_one(
        &d1,
        "SELECT * FROM attachments WHERE id = ?1 AND cipher_uuid = ?2",
        &[db::val(att_id), db::val(cipher_id)],
    ).await?;
    let att = att.ok_or_else(|| Error::not_found("Attachment not found"))?;

    let response = json!({
        "id": att.id,
        "url": format!("{}/attachments/{}/{}", domain, cipher_id, att_id),
        "fileName": att.file_name,
        "size": att.file_size,
        "sizeName": format_size(att.file_size),
        "key": att.akey,
        "object": "attachment",
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// DELETE /api/ciphers/:cipher_id/attachment/:att_id
pub async fn delete(req: Request, env: &Env, cipher_id: &str, att_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let cipher = Cipher::find_by_uuid(cipher_id, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Cipher not found"))?;

    if !cipher.is_accessible_to_user(&claims.sub, &d1).await? {
        return Err(Error::not_found("Cipher not found"));
    }

    // Delete from R2
    if let Ok(r2) = env.bucket("ATTACHMENTS") {
        let _ = r2.delete(&format!("attachments/{}/{}", cipher_id, att_id)).await;
    }

    // Delete from D1
    db::execute(
        &d1,
        "DELETE FROM attachments WHERE id = ?1 AND cipher_uuid = ?2",
        &[db::val(att_id), db::val(cipher_id)],
    ).await?;

    // Update cipher revision
    db::execute(
        &d1,
        "UPDATE ciphers SET updated_at = ?1 WHERE uuid = ?2",
        &[db::val(&util::now_utc()), db::val(cipher_id)],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

fn format_size(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{bytes} Bytes")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}
