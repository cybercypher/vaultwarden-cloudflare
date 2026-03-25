use serde_json::{json, Value};
use worker::{Env, Response};

use crate::error::{Error, Result};

/// GET /api/alive or GET /alive
pub fn alive() -> Result<Response> {
    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/now
pub fn now() -> Result<Response> {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
    Response::ok(now).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/config
pub fn config(env: &Env) -> Result<Response> {
    let domain =
        env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_else(|_| "https://vaultwarden.example.com".to_string());

    let response = json!({
        "version": "2024.12.0",
        "gitHash": "vaultwarden-cf",
        "server": {
            "name": "Vaultwarden (Cloudflare)",
            "url": "https://github.com/dani-garcia/vaultwarden",
            "wiki": ""
        },
        "environment": {
            "vault": domain,
            "api": format!("{domain}/api"),
            "identity": format!("{domain}/identity"),
            "notifications": format!("{domain}/notifications"),
            "sso": Value::Null,
            "cloudRegion": Value::Null,
        },
        "featureStates": {
            "flexible-collections-v-1": true,
        },
        "object": "config",
    });

    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/settings/domains
pub fn get_eq_domains(_env: &Env) -> Result<Response> {
    let response = json!({
        "equivalentDomains": [],
        "globalEquivalentDomains": [],
        "object": "domains",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// PUT/POST /api/settings/domains
pub async fn put_eq_domains(mut req: worker::Request, env: &Env) -> Result<Response> {
    let domain = env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default();
    let claims = crate::auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;

    let eq_domains = body["equivalentDomains"].clone();
    let excluded = body["excludedGlobalEquivalentDomains"].clone();

    crate::db::execute(
        &d1,
        "UPDATE users SET equivalent_domains = ?1, excluded_globals = ?2, updated_at = ?3 WHERE uuid = ?4",
        &[
            crate::db::val(&eq_domains.to_string()),
            crate::db::val(&excluded.to_string()),
            crate::db::val(&crate::util::now_utc()),
            crate::db::val(&claims.sub),
        ],
    )
    .await?;

    let response = json!({
        "equivalentDomains": eq_domains,
        "globalEquivalentDomains": [],
        "object": "domains",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}
