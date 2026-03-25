use serde_json::{json, Value};
use worker::{Env, Request, Response};

use crate::auth;
use crate::error::{Error, Result};
use crate::models::Folder;

/// GET /api/folders
pub async fn list(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let folders = Folder::find_by_user(&claims.sub, &d1).await?;
    let folder_list: Vec<Value> = folders.iter().map(|f| f.to_json()).collect();

    let response = json!({
        "data": folder_list,
        "object": "list",
        "continuationToken": Value::Null,
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/folders/:uuid
pub async fn get(req: Request, env: &Env, uuid: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let folder = Folder::find_by_uuid(uuid, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Folder not found"))?;

    if folder.user_uuid != claims.sub {
        return Err(Error::not_found("Folder not found"));
    }

    Response::from_json(&folder.to_json()).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/folders
pub async fn create(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let name = body["name"]
        .as_str()
        .ok_or_else(|| Error::bad_request("name is required"))?;

    let mut folder = Folder::new(claims.sub.clone(), name.to_string());
    folder.save(&d1).await?;

    crate::notifications::notify_folder_update(
        env, crate::notifications::UpdateType::SyncFolderCreate,
        &folder.uuid, &claims.sub, Some(&claims.device),
    ).await;

    Response::from_json(&folder.to_json()).map_err(|e| Error::internal(e.to_string()))
}

/// PUT /api/folders/:uuid
pub async fn update(mut req: Request, env: &Env, uuid: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let mut folder = Folder::find_by_uuid(uuid, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Folder not found"))?;

    if folder.user_uuid != claims.sub {
        return Err(Error::not_found("Folder not found"));
    }

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    if let Some(name) = body["name"].as_str() {
        folder.name = name.to_string();
    }

    folder.save(&d1).await?;

    crate::notifications::notify_folder_update(
        env, crate::notifications::UpdateType::SyncFolderUpdate,
        &folder.uuid, &claims.sub, Some(&claims.device),
    ).await;

    Response::from_json(&folder.to_json()).map_err(|e| Error::internal(e.to_string()))
}

/// DELETE /api/folders/:uuid
pub async fn delete(req: Request, env: &Env, uuid: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let folder = Folder::find_by_uuid(uuid, &d1)
        .await?
        .ok_or_else(|| Error::not_found("Folder not found"))?;

    if folder.user_uuid != claims.sub {
        return Err(Error::not_found("Folder not found"));
    }

    crate::notifications::notify_folder_update(
        env, crate::notifications::UpdateType::SyncFolderDelete,
        uuid, &claims.sub, Some(&claims.device),
    ).await;

    Folder::delete(uuid, &d1).await?;
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}
