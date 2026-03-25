use serde_json::{json, Value};
use worker::{Env, Request, Response};

use crate::auth;
use crate::error::{Error, Result};
use crate::models::cipher::{Cipher, Favorite};
use crate::models::folder::{Folder, FolderCipher};
use crate::util;

/// GET /api/ciphers
pub async fn list(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let ciphers = Cipher::find_by_user_visible(&claims.sub, &d1).await?;

    let mut cipher_list = Vec::new();
    for cipher in &ciphers {
        let folder_id = FolderCipher::find_folder_for_cipher(&cipher.uuid, &claims.sub, &d1).await?;
        let favorite = Favorite::is_favorite(&claims.sub, &cipher.uuid, &d1).await?;
        cipher_list.push(cipher.to_json(folder_id.as_deref(), favorite, &[]));
    }

    let response = json!({
        "data": cipher_list,
        "object": "list",
        "continuationToken": Value::Null,
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/ciphers/:uuid
pub async fn get(req: Request, env: &Env, uuid: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let cipher = Cipher::find_by_uuid(uuid, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Cipher not found"))?;

    if !cipher.is_accessible_to_user(&claims.sub, &d1).await? {
        return Err(Error::not_found("Cipher not found"));
    }

    let folder_id = FolderCipher::find_folder_for_cipher(&cipher.uuid, &claims.sub, &d1).await?;
    let favorite = Favorite::is_favorite(&claims.sub, &cipher.uuid, &d1).await?;

    let json = cipher.to_json(folder_id.as_deref(), favorite, &[]);
    Response::from_json(&json).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/ciphers
pub async fn create(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;

    let cipher = save_cipher_from_data(&claims.sub, None, &body, &d1).await?;

    // Validate folder ownership before associating
    let folder_id = if let Some(fid) = body["folderId"].as_str() {
        if !fid.is_empty() {
            let folder = Folder::find_by_uuid(fid, &d1).await?;
            if folder.as_ref().map(|f| f.user_uuid.as_str()) != Some(&claims.sub) {
                return Err(Error::bad_request("Folder does not belong to user"));
            }
            FolderCipher::save(&cipher.uuid, fid, &d1).await?;
            Some(fid.to_string())
        } else {
            None
        }
    } else {
        None
    };

    if let Some(fav) = body["favorite"].as_bool() {
        Favorite::set(&claims.sub, &cipher.uuid, fav, &d1).await?;
    }

    let favorite = Favorite::is_favorite(&claims.sub, &cipher.uuid, &d1).await?;
    let json = cipher.to_json(folder_id.as_deref(), favorite, &[]);

    crate::notifications::notify_cipher_update(
        env, crate::notifications::UpdateType::SyncCipherCreate,
        &cipher.uuid, &claims.sub, cipher.organization_uuid.as_deref(), Some(&claims.device),
    ).await;

    Response::from_json(&json).map_err(|e| Error::internal(e.to_string()))
}

/// PUT /api/ciphers/:uuid
pub async fn update(mut req: Request, env: &Env, uuid: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let existing = Cipher::find_by_uuid(uuid, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Cipher not found"))?;

    if !existing.is_accessible_to_user(&claims.sub, &d1).await? {
        return Err(Error::not_found("Cipher not found"));
    }

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let cipher = save_cipher_from_data(&claims.sub, Some(uuid), &body, &d1).await?;

    // Update folder association with ownership check
    FolderCipher::delete_all_for_cipher(&cipher.uuid, &d1).await?;
    let folder_id = if let Some(fid) = body["folderId"].as_str() {
        if !fid.is_empty() {
            let folder = Folder::find_by_uuid(fid, &d1).await?;
            if folder.as_ref().map(|f| f.user_uuid.as_str()) != Some(&claims.sub) {
                return Err(Error::bad_request("Folder does not belong to user"));
            }
            FolderCipher::save(&cipher.uuid, fid, &d1).await?;
            Some(fid.to_string())
        } else {
            None
        }
    } else {
        None
    };

    if let Some(fav) = body["favorite"].as_bool() {
        Favorite::set(&claims.sub, &cipher.uuid, fav, &d1).await?;
    }

    let favorite = Favorite::is_favorite(&claims.sub, &cipher.uuid, &d1).await?;
    let json = cipher.to_json(folder_id.as_deref(), favorite, &[]);

    crate::notifications::notify_cipher_update(
        env, crate::notifications::UpdateType::SyncCipherUpdate,
        &cipher.uuid, &claims.sub, cipher.organization_uuid.as_deref(), Some(&claims.device),
    ).await;

    Response::from_json(&json).map_err(|e| Error::internal(e.to_string()))
}

/// DELETE /api/ciphers/:uuid
pub async fn delete(req: Request, env: &Env, uuid: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let cipher = Cipher::find_by_uuid(uuid, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Cipher not found"))?;

    if !cipher.is_accessible_to_user(&claims.sub, &d1).await? {
        return Err(Error::not_found("Cipher not found"));
    }

    crate::notifications::notify_cipher_update(
        env, crate::notifications::UpdateType::SyncLoginDelete,
        uuid, &claims.sub, cipher.organization_uuid.as_deref(), Some(&claims.device),
    ).await;

    Cipher::delete(uuid, &d1).await?;
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// PUT /api/ciphers/:uuid/delete (soft delete / trash)
pub async fn soft_delete(req: Request, env: &Env, uuid: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let cipher = Cipher::find_by_uuid(uuid, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Cipher not found"))?;

    if !cipher.is_accessible_to_user(&claims.sub, &d1).await? {
        return Err(Error::not_found("Cipher not found"));
    }

    Cipher::soft_delete(uuid, &d1).await?;
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// PUT /api/ciphers/:uuid/restore
pub async fn restore(req: Request, env: &Env, uuid: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let cipher = Cipher::find_by_uuid(uuid, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Cipher not found"))?;

    if !cipher.is_accessible_to_user(&claims.sub, &d1).await? {
        return Err(Error::not_found("Cipher not found"));
    }

    Cipher::restore(uuid, &d1).await?;

    let folder_id = FolderCipher::find_folder_for_cipher(&cipher.uuid, &claims.sub, &d1).await?;
    let favorite = Favorite::is_favorite(&claims.sub, &cipher.uuid, &d1).await?;
    let json = cipher.to_json(folder_id.as_deref(), favorite, &[]);
    Response::from_json(&json).map_err(|e| Error::internal(e.to_string()))
}

/// Import ciphers (POST /api/ciphers/import)
pub async fn import(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;

    // Import folders
    let folders = body["folders"].as_array();
    let mut folder_id_map: std::collections::HashMap<usize, String> = std::collections::HashMap::new();

    if let Some(folders) = folders {
        for (i, f) in folders.iter().enumerate() {
            if let Some(name) = f["name"].as_str() {
                let mut folder = crate::models::Folder::new(claims.sub.clone(), name.to_string());
                folder.save(&d1).await?;
                folder_id_map.insert(i, folder.uuid);
            }
        }
    }

    // Import ciphers
    if let Some(ciphers) = body["ciphers"].as_array() {
        let folder_relationships = body["folderRelationships"].as_array();

        for (i, cipher_data) in ciphers.iter().enumerate() {
            let cipher = save_cipher_from_data(&claims.sub, None, cipher_data, &d1).await?;

            // Check folder relationship
            if let Some(rels) = folder_relationships {
                for rel in rels {
                    if rel["key"].as_u64() == Some(i as u64) {
                        if let Some(folder_idx) = rel["value"].as_u64() {
                            if let Some(folder_uuid) = folder_id_map.get(&(folder_idx as usize)) {
                                FolderCipher::save(&cipher.uuid, folder_uuid, &d1).await?;
                            }
                        }
                    }
                }
            }
        }
    }

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// DELETE /api/ciphers (bulk delete selected ciphers)
pub async fn delete_selected(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let ids = body["ids"]
        .as_array()
        .ok_or_else(|| Error::bad_request("ids array required"))?;

    for id in ids {
        if let Some(uuid) = id.as_str() {
            if let Some(cipher) = Cipher::find_by_uuid(uuid, &d1).await? {
                if cipher.is_accessible_to_user(&claims.sub, &d1).await? {
                    Cipher::delete(uuid, &d1).await?;
                }
            }
        }
    }

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// PUT /api/ciphers/move (move ciphers to a folder)
pub async fn move_selected(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let folder_id = body["folderId"].as_str();
    let ids = body["ids"]
        .as_array()
        .ok_or_else(|| Error::bad_request("ids array required"))?;

    // Validate folder ownership if a folder is specified
    if let Some(fid) = folder_id {
        if !fid.is_empty() {
            let folder = Folder::find_by_uuid(fid, &d1).await?;
            if folder.as_ref().map(|f| f.user_uuid.as_str()) != Some(&claims.sub) {
                return Err(Error::bad_request("Folder does not belong to user"));
            }
        }
    }

    for id in ids {
        if let Some(uuid) = id.as_str() {
            if let Some(cipher) = Cipher::find_by_uuid(uuid, &d1).await? {
                if cipher.is_accessible_to_user(&claims.sub, &d1).await? {
                    FolderCipher::delete_all_for_cipher(uuid, &d1).await?;
                    if let Some(fid) = folder_id {
                        if !fid.is_empty() {
                            FolderCipher::save(uuid, fid, &d1).await?;
                        }
                    }
                }
            }
        }
    }

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/ciphers/purge (delete all user ciphers)
pub async fn purge(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let master_password_hash = body["masterPasswordHash"]
        .as_str()
        .ok_or_else(|| Error::bad_request("masterPasswordHash required"))?;

    let user = crate::models::User::find_by_uuid(&claims.sub, &d1)
        .await?
        .ok_or_else(|| Error::not_found("User not found"))?;

    if !user.check_valid_password(master_password_hash) {
        return Err(Error::bad_request("Invalid password"));
    }

    // Delete all personal ciphers and their relations
    crate::db::execute(
        &d1,
        "DELETE FROM folders_ciphers WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE user_uuid = ?1)",
        &[crate::db::val(&claims.sub)],
    ).await?;
    crate::db::execute(
        &d1,
        "DELETE FROM favorites WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE user_uuid = ?1)",
        &[crate::db::val(&claims.sub)],
    ).await?;
    crate::db::execute(
        &d1,
        "DELETE FROM attachments WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE user_uuid = ?1)",
        &[crate::db::val(&claims.sub)],
    ).await?;
    crate::db::execute(
        &d1,
        "DELETE FROM ciphers WHERE user_uuid = ?1",
        &[crate::db::val(&claims.sub)],
    ).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

// ============================================================================
// Helper: Create or update a cipher from JSON data
// ============================================================================

async fn save_cipher_from_data(
    user_uuid: &str,
    existing_uuid: Option<&str>,
    data: &Value,
    d1: &worker::D1Database,
) -> Result<Cipher> {
    let atype = data["type"]
        .as_i64()
        .ok_or_else(|| Error::bad_request("type is required"))? as i32;
    let name = data["name"]
        .as_str()
        .ok_or_else(|| Error::bad_request("name is required"))?
        .to_string();

    let mut cipher = if let Some(uuid) = existing_uuid {
        let mut c = Cipher::find_by_uuid(uuid, d1)
            .await?
            .ok_or_else(|| Error::not_found("Cipher not found"))?;
        c.updated_at = util::now_utc();
        c.atype = atype;
        c.name = name;
        c
    } else {
        let mut c = Cipher::new(atype, name);
        c.user_uuid = Some(user_uuid.to_string());
        c
    };

    cipher.notes = data["notes"].as_str().map(|s| s.to_string());
    cipher.fields = data.get("fields").and_then(|f| {
        if f.is_null() { None } else { Some(f.to_string()) }
    });
    cipher.password_history = data.get("passwordHistory").and_then(|p| {
        if p.is_null() { None } else { Some(p.to_string()) }
    });
    cipher.reprompt = data["reprompt"].as_i64().map(|r| r as i32);
    cipher.akey = data["key"].as_str().map(|s| s.to_string());

    // Validate organization membership before assigning org cipher
    if let Some(org_id) = data["organizationId"].as_str() {
        if !org_id.is_empty() {
            let member: Option<serde_json::Value> = crate::db::query_one(
                d1,
                "SELECT uuid FROM users_organizations WHERE user_uuid = ?1 AND org_uuid = ?2 AND status = 2",
                &[crate::db::val(user_uuid), crate::db::val(org_id)],
            ).await?;
            if member.is_none() {
                return Err(Error::bad_request("Not a confirmed member of this organization"));
            }
            cipher.organization_uuid = Some(org_id.to_string());
            cipher.user_uuid = None; // Org ciphers don't have user_uuid
        }
    }

    // Store the type-specific data
    let type_data = match atype {
        1 => data.get("login"),
        2 => data.get("secureNote"),
        3 => data.get("card"),
        4 => data.get("identity"),
        5 => data.get("sshKey"),
        _ => None,
    };
    cipher.data = type_data.map(|d| d.to_string()).unwrap_or_else(|| "{}".to_string());

    cipher.save(d1).await?;
    Ok(cipher)
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}
