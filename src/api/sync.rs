use serde_json::{json, Value};
use worker::{Env, Request, Response};

use crate::auth;
use crate::error::{Error, Result};
use crate::models::*;

/// GET /api/sync
/// Returns the complete vault state for the authenticated user.
pub async fn sync(req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let user = User::find_by_uuid(&claims.sub, &d1)
        .await?
        .ok_or_else(|| Error::not_found("User not found"))?;

    // Fetch all user data in parallel (D1 is sequential per-request, but still structured)
    let folders = Folder::find_by_user(&user.uuid, &d1).await?;
    let ciphers = Cipher::find_by_user(&user.uuid, &d1).await?;
    let collections = Collection::find_by_user(&user.uuid, &d1).await?;
    let sends = Send::find_by_user(&user.uuid, &d1).await?;
    let memberships = Membership::find_confirmed_by_user(&user.uuid, &d1).await?;

    // Build organization list
    let mut org_list = Vec::new();
    for m in &memberships {
        if let Some(org) = Organization::find_by_uuid(&m.org_uuid, &d1).await? {
            org_list.push(org.to_json(m));
        }
    }

    // Build cipher JSON list with folder/favorite info
    let mut cipher_list = Vec::new();
    for cipher in &ciphers {
        let folder_id = FolderCipher::find_folder_for_cipher(&cipher.uuid, &user.uuid, &d1).await?;
        let favorite = crate::models::cipher::Favorite::is_favorite(&user.uuid, &cipher.uuid, &d1).await?;
        let collection_ids = CollectionCipher::find_collections_for_cipher(&cipher.uuid, &d1).await?;

        let mut cipher_json = cipher.to_json(folder_id.as_deref(), favorite, &[]);
        cipher_json["collectionIds"] = Value::Array(
            collection_ids.into_iter().map(Value::String).collect(),
        );
        cipher_list.push(cipher_json);
    }

    // Build profile with orgs
    let mut profile = user.to_json();
    profile["organizations"] = Value::Array(org_list);

    // Global equivalent domains
    let equivalent_domains: Value = serde_json::from_str(&user.equivalent_domains).unwrap_or(json!([]));
    let excluded_globals: Value = serde_json::from_str(&user.excluded_globals).unwrap_or(json!([]));

    let response = json!({
        "profile": profile,
        "folders": folders.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
        "collections": collections.iter().map(|c| c.to_json()).collect::<Vec<_>>(),
        "ciphers": cipher_list,
        "domains": {
            "equivalentDomains": equivalent_domains,
            "globalEquivalentDomains": [],
            "object": "domains"
        },
        "policies": [],
        "sends": sends.iter().map(|s| s.to_json()).collect::<Vec<_>>(),
        "unofficialServer": true,
        "object": "sync"
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}
