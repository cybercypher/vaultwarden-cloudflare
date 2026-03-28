#![recursion_limit = "256"]
#![allow(unused_variables, unused_mut)]

#[macro_use]
mod error;
mod api;
mod auth;
mod crypto;
mod db;
mod mail;
mod models;
mod notifications;
mod storage;
mod util;

use serde_json::{json, Value};
use worker::*;

fn add_cors_headers(resp: &mut Response, env: &Env) {
    let allowed_origin = env.var("CORS_ALLOWED_ORIGIN").map(|v| v.to_string()).unwrap_or_else(|_| {
        // Default to configured DOMAIN if no explicit CORS origin set
        env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_else(|_| "*".to_string())
    });
    let headers = resp.headers_mut();
    let _ = headers.set("Access-Control-Allow-Origin", &allowed_origin);
    let _ = headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
    let _ = headers.set(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, Accept, Device-Type, Bitwarden-Client-Name, Bitwarden-Client-Version, Auth-Email",
    );
    let _ = headers.set("Access-Control-Max-Age", "86400");
}

/// Helper to extract a path segment by position (0-indexed after the base path).
fn path_segment(path: &str, base: &str, index: usize) -> Option<String> {
    let rest = path.strip_prefix(base).unwrap_or(path);
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    segments.get(index).map(|s| s.to_string())
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    // Handle CORS preflight
    if req.method() == Method::Options {
        let mut resp = Response::ok("").unwrap();
        add_cors_headers(&mut resp, &env);
        return Ok(resp);
    }

    let url = req.url()?;
    let path = url.path();
    let method = req.method();

    let result = route(req, &env, &path, method, &url).await;

    let mut resp = match result {
        Ok(r) => r,
        Err(e) => e.into_response(),
    };

    add_cors_headers(&mut resp, &env);
    Ok(resp)
}

async fn route(req: Request, env: &Env, path: &str, method: Method, url: &worker::Url) -> error::Result<Response> {
    // =========================================================================
    // Identity routes (/identity/...)
    // =========================================================================
    if path == "/identity/connect/token" && method == Method::Post {
        return api::identity::login(req, env).await;
    }
    if path == "/identity/accounts/prelogin" && method == Method::Post {
        return api::identity::prelogin(req, env).await;
    }
    if path == "/identity/accounts/register" && method == Method::Post {
        return api::identity::register(req, env).await;
    }
    if path == "/identity/accounts/register/send-verification-email" && method == Method::Post {
        return api::identity::register(req, env).await;
    }
    if path == "/identity/accounts/register/finish" && method == Method::Post {
        return api::identity::register(req, env).await;
    }
    // SSO routes
    if (path == "/identity/connect/authorize" || path.starts_with("/identity/connect/authorize?"))
        && method == Method::Get
    {
        return api::sso::authorize(req, env).await;
    }
    if path.starts_with("/identity/connect/oidc-signin") && method == Method::Get {
        return api::sso::oidc_signin(req, env).await;
    }
    if path == "/identity/sso/prevalidate" && method == Method::Get {
        return api::sso::prevalidate(req, env).await;
    }

    // =========================================================================
    // Notifications: WebSocket hub (Durable Object proxy)
    // =========================================================================
    if (path == "/notifications/hub" || path == "/notifications/hub/") && method == Method::Get {
        // Extract access_token from query string
        let token = url.query_pairs().find(|(k, _)| k == "access_token").map(|(_, v)| v.to_string());

        if let Some(token) = token {
            let domain = env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default();
            let claims = auth::decode_login(&token, &domain, env)
                .map_err(|_| error::Error::unauthorized("Invalid access token"))?;

            // Forward to the user's Durable Object for WebSocket handling
            let namespace = env
                .durable_object("NOTIFICATION_HUB")
                .map_err(|e| error::Error::internal(format!("DO binding error: {e}")))?;
            let id =
                namespace.id_from_name(&claims.sub).map_err(|e| error::Error::internal(format!("DO id error: {e}")))?;
            let stub = id.get_stub().map_err(|e| error::Error::internal(format!("DO stub error: {e}")))?;

            let do_req = Request::new(&format!("https://do-internal/ws"), Method::Get)
                .map_err(|e| error::Error::internal(format!("DO request error: {e}")))?;

            let resp = stub
                .fetch_with_request(do_req)
                .await
                .map_err(|e| error::Error::internal(format!("DO fetch error: {e}")))?;

            return Ok(resp);
        } else {
            return Err(error::Error::unauthorized("access_token required"));
        }
    }
    if path == "/notifications/hub/negotiate" && method == Method::Post {
        // SignalR negotiate - tell client to use WebSocket transport
        let response = json!({
            "negotiateVersion": 1,
            "connectionId": util::get_uuid(),
            "connectionToken": util::get_uuid(),
            "availableTransports": [{
                "transport": "WebSockets",
                "transferFormats": ["Binary"]
            }]
        });
        return Response::from_json(&response).map_err(|e| error::Error::internal(e.to_string()));
    }
    if path == "/notifications/anonymous-hub" || path == "/notifications/anonymous-hub/" {
        // Anonymous hub is not supported, return negotiate response pointing to WebSocket
        if method == Method::Post || path.contains("negotiate") {
            let response = json!({
                "negotiateVersion": 1,
                "connectionId": util::get_uuid(),
                "availableTransports": [{"transport": "WebSockets", "transferFormats": ["Binary"]}]
            });
            return Response::from_json(&response).map_err(|e| error::Error::internal(e.to_string()));
        }
    }

    // =========================================================================
    // API: Config / Health
    // =========================================================================
    if path == "/api/alive" || path == "/alive" {
        return api::core::alive();
    }
    if path == "/api/now" {
        return api::core::now();
    }
    if path == "/api/config" {
        return api::core::config(env);
    }

    // =========================================================================
    // API: Accounts
    // =========================================================================
    if path == "/api/accounts/register" && method == Method::Post {
        return api::identity::register(req, env).await;
    }
    if path == "/api/accounts/profile" {
        return match method {
            Method::Get => api::accounts::profile(req, env).await,
            Method::Put | Method::Post => api::accounts::put_profile(req, env).await,
            _ => Err(error::Error::new("Method not allowed", 405)),
        };
    }
    if path == "/api/accounts/keys" && method == Method::Post {
        return api::accounts::post_keys(req, env).await;
    }
    if path == "/api/accounts/revision-date" && method == Method::Get {
        return api::accounts::revision_date(req, env).await;
    }
    if path == "/api/accounts/password-hint" && method == Method::Post {
        return api::accounts::password_hint(req, env).await;
    }
    if path == "/api/accounts/verify-password" && method == Method::Post {
        return api::accounts::verify_password(req, env).await;
    }
    if path == "/api/accounts/kdf" && method == Method::Post {
        return api::accounts::post_kdf(req, env).await;
    }
    if path == "/api/accounts/prelogin" && method == Method::Post {
        return api::identity::prelogin(req, env).await;
    }

    // =========================================================================
    // API: Sync
    // =========================================================================
    if path == "/api/sync" && method == Method::Get {
        return api::sync::sync(req, env).await;
    }

    // =========================================================================
    // API: Folders
    // =========================================================================
    if path == "/api/folders" {
        return match method {
            Method::Get => api::folders::list(req, env).await,
            Method::Post => api::folders::create(req, env).await,
            _ => Err(error::Error::new("Method not allowed", 405)),
        };
    }
    if path.starts_with("/api/folders/") {
        if let Some(uuid) = path_segment(path, "/api/folders/", 0) {
            return match method {
                Method::Get => api::folders::get(req, env, &uuid).await,
                Method::Put | Method::Post => api::folders::update(req, env, &uuid).await,
                Method::Delete => api::folders::delete(req, env, &uuid).await,
                _ => Err(error::Error::new("Method not allowed", 405)),
            };
        }
    }

    // =========================================================================
    // API: Ciphers
    // =========================================================================
    if path == "/api/ciphers" {
        return match method {
            Method::Get => api::ciphers::list(req, env).await,
            Method::Post => api::ciphers::create(req, env).await,
            Method::Delete => api::ciphers::delete_selected(req, env).await,
            _ => Err(error::Error::new("Method not allowed", 405)),
        };
    }
    if path == "/api/ciphers/create" && method == Method::Post {
        return api::ciphers::create(req, env).await;
    }
    if path.starts_with("/api/ciphers/organization-details") && method == Method::Get {
        let response = json!({"data": [], "object": "list", "continuationToken": Value::Null});
        return Response::from_json(&response).map_err(|e| error::Error::internal(e.to_string()));
    }
    if path == "/api/ciphers/import" && method == Method::Post {
        return api::ciphers::import(req, env).await;
    }
    if (path == "/api/ciphers/delete" || path == "/api/ciphers/delete-admin")
        && (method == Method::Post || method == Method::Put)
    {
        return api::ciphers::delete_selected(req, env).await;
    }
    if (path == "/api/ciphers/move") && (method == Method::Post || method == Method::Put) {
        return api::ciphers::move_selected(req, env).await;
    }
    if path == "/api/ciphers/purge" && method == Method::Post {
        return api::ciphers::purge(req, env).await;
    }
    if path.starts_with("/api/ciphers/") {
        if let Some(uuid) = path_segment(path, "/api/ciphers/", 0) {
            let sub = path_segment(path, "/api/ciphers/", 1);
            match sub.as_deref() {
                Some("delete") | Some("delete-admin") => {
                    return api::ciphers::soft_delete(req, env, &uuid).await;
                }
                Some("restore") | Some("restore-admin") => {
                    return api::ciphers::restore(req, env, &uuid).await;
                }
                Some("admin") if method == Method::Get => {
                    return api::ciphers::get(req, env, &uuid).await;
                }
                Some("details") if method == Method::Get => {
                    return api::ciphers::get(req, env, &uuid).await;
                }
                None => {
                    return match method {
                        Method::Get => api::ciphers::get(req, env, &uuid).await,
                        Method::Put | Method::Post => api::ciphers::update(req, env, &uuid).await,
                        Method::Delete => api::ciphers::delete(req, env, &uuid).await,
                        _ => Err(error::Error::new("Method not allowed", 405)),
                    };
                }
                _ => {}
            }
        }
    }

    // =========================================================================
    // API: Folders (additional routes)
    // =========================================================================
    if path.starts_with("/api/folders/") {
        if let Some(uuid) = path_segment(path, "/api/folders/", 0) {
            let sub = path_segment(path, "/api/folders/", 1);
            if sub.as_deref() == Some("delete") && method == Method::Post {
                return api::folders::delete(req, env, &uuid).await;
            }
        }
    }

    // =========================================================================
    // API: Settings / Domains
    // =========================================================================
    if path == "/api/settings/domains" {
        return match method {
            Method::Get => api::core::get_eq_domains(env),
            Method::Put | Method::Post => api::core::put_eq_domains(req, env).await,
            _ => Err(error::Error::new("Method not allowed", 405)),
        };
    }

    // =========================================================================
    // API: Misc endpoints clients expect
    // =========================================================================
    if path == "/api/accounts/password" && method == Method::Post {
        return api::accounts::post_password(req, env).await;
    }
    if path == "/api/accounts/delete" && method == Method::Post {
        return api::accounts::delete_account(req, env).await;
    }
    if path == "/api/accounts" && method == Method::Delete {
        return api::accounts::delete_account(req, env).await;
    }
    if path == "/api/accounts/security-stamp" && method == Method::Post {
        return api::accounts::post_security_stamp(req, env).await;
    }
    if path == "/api/accounts/api-key" && method == Method::Post {
        return api::accounts::get_api_key(req, env).await;
    }
    if path == "/api/accounts/rotate-api-key" && method == Method::Post {
        return api::accounts::rotate_api_key(req, env).await;
    }
    if path == "/api/devices" && method == Method::Get {
        return api::accounts::get_devices(req, env).await;
    }
    if path == "/api/collections" && method == Method::Get {
        return api::accounts::get_collections(req, env).await;
    }

    // =========================================================================
    // API: Two-Factor Authentication
    // =========================================================================
    if path == "/api/two-factor" && method == Method::Get {
        return api::twofactor::get_twofactor(req, env).await;
    }
    if path == "/api/two-factor/get-authenticator" && method == Method::Post {
        return api::twofactor::get_authenticator(req, env).await;
    }
    if path == "/api/two-factor/authenticator" && (method == Method::Post || method == Method::Put) {
        return api::twofactor::activate_authenticator(req, env).await;
    }
    if path == "/api/two-factor/disable" && (method == Method::Post || method == Method::Put) {
        return api::twofactor::disable_twofactor(req, env).await;
    }
    if path == "/api/two-factor/get-recover" && method == Method::Post {
        return api::twofactor::get_recover(req, env).await;
    }
    if path == "/api/two-factor/get-email" && method == Method::Post {
        return api::twofactor::get_email(req, env).await;
    }
    if path == "/api/two-factor/email" && method == Method::Put {
        return api::twofactor::activate_email(req, env).await;
    }
    if path == "/api/two-factor/send-email-login" && method == Method::Post {
        return api::twofactor::send_email_login(req, env).await;
    }
    if path == "/api/two-factor/send-email" && method == Method::Post {
        return api::twofactor::send_email(req, env).await;
    }
    if path == "/api/two-factor/get-device-verification-settings" && method == Method::Get {
        return api::twofactor::get_device_verification_settings();
    }

    // =========================================================================
    // API: Sends
    // =========================================================================
    if path == "/api/sends" {
        return match method {
            Method::Get => api::sends::list(req, env).await,
            Method::Post => api::sends::create(req, env).await,
            _ => Err(error::Error::new("Method not allowed", 405)),
        };
    }
    if path == "/api/sends/file/v2" && method == Method::Post {
        return api::sends::create_file_v2(req, env).await;
    }
    if path == "/api/sends/file" && method == Method::Post {
        return api::sends::create(req, env).await;
    }
    if path.starts_with("/api/sends/access/") {
        if let Some(access_id) = path_segment(path, "/api/sends/access/", 0) {
            return api::sends::access(req, env, &access_id).await;
        }
    }
    if path.starts_with("/api/sends/") {
        if let Some(send_id) = path_segment(path, "/api/sends/", 0) {
            let sub = path_segment(path, "/api/sends/", 1);
            match sub.as_deref() {
                Some("remove-password") if method == Method::Put => {
                    return api::sends::remove_password(req, env, &send_id).await;
                }
                Some("file") => {
                    if let Some(file_id) = path_segment(path, "/api/sends/", 2) {
                        return api::sends::upload_file(req, env, &send_id, &file_id).await;
                    }
                }
                Some("access") => {
                    // /api/sends/:id/access/file/:file_id
                    if let Some(file_sub) = path_segment(path, "/api/sends/", 2) {
                        if file_sub == "file" {
                            if let Some(file_id) = path_segment(path, "/api/sends/", 3) {
                                return api::sends::access_file(req, env, &send_id, &file_id).await;
                            }
                        }
                    }
                }
                Some(file_id) if method == Method::Get => {
                    // /api/sends/:send_id/:file_id?t=... (direct download)
                    return api::sends::download_file(req, env, &send_id, file_id).await;
                }
                None => {
                    return match method {
                        Method::Get => api::sends::get(req, env, &send_id).await,
                        Method::Put => api::sends::update(req, env, &send_id).await,
                        Method::Delete => api::sends::delete(req, env, &send_id).await,
                        _ => Err(error::Error::new("Method not allowed", 405)),
                    };
                }
                _ => {}
            }
        }
    }

    // =========================================================================
    // API: Organizations
    // =========================================================================
    if path == "/api/organizations" && method == Method::Post {
        return api::organizations::create(req, env).await;
    }
    if path == "/api/plans" && method == Method::Get {
        return api::organizations::get_plans();
    }
    if path.starts_with("/api/organizations/") {
        if let Some(org_id) = path_segment(path, "/api/organizations/", 0) {
            let sub = path_segment(path, "/api/organizations/", 1);
            match sub.as_deref() {
                Some("delete") if method == Method::Post => {
                    return api::organizations::delete_org(req, env, &org_id).await;
                }
                Some("leave") if method == Method::Post => {
                    return api::organizations::leave(req, env, &org_id).await;
                }
                Some("keys") if method == Method::Get => {
                    return api::organizations::get_org_keys(req, env, &org_id).await;
                }
                Some("users") => {
                    let user_sub = path_segment(path, "/api/organizations/", 2);
                    match user_sub.as_deref() {
                        Some("invite") if method == Method::Post => {
                            return api::organizations::invite_member(req, env, &org_id).await;
                        }
                        Some("mini-details") if method == Method::Get => {
                            return api::organizations::get_members(req, env, &org_id).await;
                        }
                        Some(member_id) => {
                            let member_sub = path_segment(path, "/api/organizations/", 3);
                            match member_sub.as_deref() {
                                Some("confirm") if method == Method::Post => {
                                    return api::organizations::confirm_member(req, env, &org_id, member_id).await;
                                }
                                Some("accept") if method == Method::Post => {
                                    return api::organizations::accept_invite(req, env, &org_id, member_id).await;
                                }
                                None if method == Method::Delete => {
                                    return api::organizations::delete_member(req, env, &org_id, member_id).await;
                                }
                                _ => {}
                            }
                        }
                        None => {
                            return api::organizations::get_members(req, env, &org_id).await;
                        }
                    }
                }
                Some("collections") => {
                    let col_sub = path_segment(path, "/api/organizations/", 2);
                    match col_sub.as_deref() {
                        Some("details") if method == Method::Get => {
                            return api::organizations::get_collections(req, env, &org_id).await;
                        }
                        Some(col_id) => {
                            let col_action = path_segment(path, "/api/organizations/", 3);
                            match col_action.as_deref() {
                                Some("delete") if method == Method::Post => {
                                    return api::organizations::delete_collection(req, env, &org_id, col_id).await;
                                }
                                Some("details") if method == Method::Get => {
                                    return api::organizations::get_collections(req, env, &org_id).await;
                                }
                                None if method == Method::Delete => {
                                    return api::organizations::delete_collection(req, env, &org_id, col_id).await;
                                }
                                _ => {}
                            }
                        }
                        None => {
                            return match method {
                                Method::Get => api::organizations::get_collections(req, env, &org_id).await,
                                Method::Post => api::organizations::create_collection(req, env, &org_id).await,
                                _ => Err(error::Error::new("Method not allowed", 405)),
                            };
                        }
                    }
                }
                Some("policies") if method == Method::Get => {
                    // Return empty policies list
                    let response = json!({"data": [], "object": "list", "continuationToken": Value::Null});
                    return Response::from_json(&response).map_err(|e| error::Error::internal(e.to_string()));
                }
                Some("billing") => {
                    let response = json!({"object": "billingMetadata"});
                    return Response::from_json(&response).map_err(|e| error::Error::internal(e.to_string()));
                }
                None => {
                    return match method {
                        Method::Get => api::organizations::get_org(req, env, &org_id).await,
                        Method::Delete => api::organizations::delete_org(req, env, &org_id).await,
                        _ => Err(error::Error::new("Method not allowed", 405)),
                    };
                }
                _ => {}
            }
        }
    }

    // =========================================================================
    // API: Cipher attachments (R2)
    // =========================================================================
    if path.starts_with("/api/ciphers/") {
        if let Some(cipher_id) = path_segment(path, "/api/ciphers/", 0) {
            if path_segment(path, "/api/ciphers/", 1).as_deref() == Some("attachment") {
                let att_sub = path_segment(path, "/api/ciphers/", 2);
                match att_sub.as_deref() {
                    Some("v2") if method == Method::Post => {
                        return api::attachments::create_v2(req, env, &cipher_id).await;
                    }
                    Some(att_id) => {
                        let att_action = path_segment(path, "/api/ciphers/", 3);
                        match att_action.as_deref() {
                            Some("delete") | Some("delete-admin") if method == Method::Post => {
                                return api::attachments::delete(req, env, &cipher_id, att_id).await;
                            }
                            None if method == Method::Delete => {
                                return api::attachments::delete(req, env, &cipher_id, att_id).await;
                            }
                            None if method == Method::Post => {
                                return api::attachments::upload(req, env, &cipher_id, att_id).await;
                            }
                            None if method == Method::Get => {
                                return api::attachments::get(req, env, &cipher_id, att_id).await;
                            }
                            _ => {}
                        }
                    }
                    None if method == Method::Post => {
                        return api::attachments::create_v2(req, env, &cipher_id).await;
                    }
                    _ => {}
                }
            }
        }
    }

    // =========================================================================
    // API: Emergency Access
    // =========================================================================
    if path == "/api/emergency-access/trusted" && method == Method::Get {
        return api::emergency::get_contacts(req, env).await;
    }
    if path == "/api/emergency-access/granted" && method == Method::Get {
        return api::emergency::get_grantees(req, env).await;
    }
    if path == "/api/emergency-access/invite" && method == Method::Post {
        return api::emergency::invite(req, env).await;
    }
    if path.starts_with("/api/emergency-access/") {
        if let Some(ea_id) = path_segment(path, "/api/emergency-access/", 0) {
            if ea_id != "trusted" && ea_id != "granted" && ea_id != "invite" {
                let sub = path_segment(path, "/api/emergency-access/", 1);
                match sub.as_deref() {
                    Some("accept") if method == Method::Post => return api::emergency::accept(req, env, &ea_id).await,
                    Some("confirm") if method == Method::Post => {
                        return api::emergency::confirm(req, env, &ea_id).await
                    }
                    Some("initiate") if method == Method::Post => {
                        return api::emergency::initiate(req, env, &ea_id).await
                    }
                    Some("approve") if method == Method::Post => {
                        return api::emergency::approve(req, env, &ea_id).await
                    }
                    Some("reject") if method == Method::Post => return api::emergency::reject(req, env, &ea_id).await,
                    Some("view") if method == Method::Post => return api::emergency::view(req, env, &ea_id).await,
                    Some("takeover") if method == Method::Post => {
                        return api::emergency::takeover(req, env, &ea_id).await
                    }
                    Some("delete") if method == Method::Post => {
                        return api::emergency::delete_ea(req, env, &ea_id).await
                    }
                    Some("policies") if method == Method::Get => {
                        return api::emergency::policies(req, env, &ea_id).await
                    }
                    None if method == Method::Delete => return api::emergency::delete_ea(req, env, &ea_id).await,
                    _ => {}
                }
            }
        }
    }

    // =========================================================================
    // API: Events (collect + list)
    // =========================================================================
    if path == "/api/collect" && method == Method::Post {
        // Require authentication for event collection
        let domain_for_events = env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default();
        let _event_claims = auth::get_auth_user(&req, &domain_for_events, env)
            .map_err(|_| error::Error::unauthorized("Authentication required"))?;
        // Store client-reported events in D1
        if let Ok(d1) = env.d1("DB") {
            if let Ok(mut req) = Ok::<Request, error::Error>(req) {
                if let Ok(body) = req.json::<Vec<Value>>().await {
                    for event in body {
                        let _ = db::execute(
                            &d1,
                            "INSERT INTO event (uuid, event_type, user_uuid, cipher_uuid, event_date, ip_address, device_type)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                            &[
                                db::val(&util::get_uuid()),
                                db::val_i32(event["type"].as_i64().unwrap_or(0) as i32),
                                db::val_opt(&event["userId"].as_str().map(|s| s.to_string())),
                                db::val_opt(&event["cipherId"].as_str().map(|s| s.to_string())),
                                db::val(&event["date"].as_str().unwrap_or(&util::now_utc()).to_string()),
                                db::val_opt(&None::<String>),
                                db::val_opt_i32(event["deviceType"].as_i64().map(|n| n as i32)),
                            ],
                        ).await;
                    }
                }
                return Response::ok("").map_err(|e| error::Error::internal(e.to_string()));
            }
        }
        return Response::ok("").map_err(|e| error::Error::internal(e.to_string()));
    }

    // =========================================================================
    // API: Misc endpoints for client compatibility
    // =========================================================================
    if path == "/api/accounts/set-password" && method == Method::Post {
        return api::accounts::post_password(req, env).await;
    }
    if path == "/api/accounts/avatar" && method == Method::Put {
        return api::accounts::put_profile(req, env).await;
    }
    if path.starts_with("/api/users/") && path.ends_with("/public-key") && method == Method::Get {
        // Return empty public key for unknown users
        let response = json!({"userId": "", "publicKey": Value::Null, "object": "userKey"});
        return Response::from_json(&response).map_err(|e| error::Error::internal(e.to_string()));
    }
    if path == "/api/accounts/verify-email" && method == Method::Post {
        // Mark email as verified
        let domain = env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default();
        if let Ok(claims) = auth::get_auth_user(&req, &domain, env) {
            if let Ok(d1) = env.d1("DB") {
                let _ = db::execute(
                    &d1,
                    "UPDATE users SET verified_at = ?1 WHERE uuid = ?2",
                    &[db::val(&util::now_utc()), db::val(&claims.sub)],
                )
                .await;
            }
        }
        return Response::ok("").map_err(|e| error::Error::internal(e.to_string()));
    }
    if path == "/api/accounts/verify-email-token" && method == Method::Post {
        // Token-based email verification — requires authentication
        let domain = env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default();
        if let Ok(claims) = auth::get_auth_user(&req, &domain, env) {
            if let Ok(d1) = env.d1("DB") {
                // Only verify the authenticated user's own email
                let _ = db::execute(
                    &d1,
                    "UPDATE users SET verified_at = ?1 WHERE uuid = ?2",
                    &[db::val(&util::now_utc()), db::val(&claims.sub)],
                )
                .await;
            }
        }
        return Response::ok("").map_err(|e| error::Error::internal(e.to_string()));
    }
    if path == "/api/accounts/delete-recover" && method == Method::Post {
        // Send account deletion recovery email
        if let Ok(mut req) = Ok::<Request, error::Error>(req) {
            if let Ok(body) = req.json::<Value>().await {
                if let Some(email) = body["email"].as_str() {
                    let token = util::get_uuid();
                    let _ = mail::send_delete_account(env, email, &token).await;
                }
            }
        }
        return Response::ok("").map_err(|e| error::Error::internal(e.to_string()));
    }
    if path == "/api/accounts/delete-recover-token" && method == Method::Post {
        return api::accounts::delete_account(req, env).await;
    }
    if path == "/api/tasks" && method == Method::Get {
        let response = json!({"data": [], "object": "list", "continuationToken": Value::Null});
        return Response::from_json(&response).map_err(|e| error::Error::internal(e.to_string()));
    }
    if path == "/api/devices/knowndevice" && method == Method::Get {
        return Response::ok("false").map_err(|e| error::Error::internal(e.to_string()));
    }
    if path == "/api/accounts/key-management/rotate-user-account-keys" && method == Method::Post {
        return api::accounts::post_kdf(req, env).await;
    }
    if path.starts_with("/api/organizations/") && path.contains("/events") && method == Method::Get {
        let response = json!({"data": [], "object": "list", "continuationToken": Value::Null});
        return Response::from_json(&response).map_err(|e| error::Error::internal(e.to_string()));
    }
    if path == "/api/hibp/breach" && method == Method::Get {
        return Response::from_json(&json!([])).map_err(|e| error::Error::internal(e.to_string()));
    }
    if path == "/api/version" && method == Method::Get {
        return Response::ok("2024.12.0").map_err(|e| error::Error::internal(e.to_string()));
    }

    // =========================================================================
    // Admin API
    // =========================================================================
    // GET /admin is served by CF Pages (web-vault/admin.html)
    // Only POST /admin (login API) is handled by the Worker
    if path == "/admin" && method == Method::Post {
        return api::admin::admin_login(req, env).await;
    }
    if path == "/admin/users" && method == Method::Get {
        return api::admin::get_users(req, env).await;
    }
    if path == "/admin/users/overview" && method == Method::Get {
        return api::admin::get_users(req, env).await;
    }
    if path == "/admin/users/update_revision" && method == Method::Post {
        return api::admin::update_all_revisions(req, env).await;
    }
    if path == "/admin/invite" && method == Method::Post {
        return api::admin::invite_user(req, env).await;
    }
    if path == "/admin/organizations/overview" && method == Method::Get {
        return api::admin::organizations_overview(req, env).await;
    }
    if path == "/admin/diagnostics" && method == Method::Get {
        return api::admin::diagnostics(req, env).await;
    }
    if path == "/admin/diagnostics/config" && method == Method::Get {
        return api::admin::get_config(req, env).await;
    }
    if path.starts_with("/admin/diagnostics/http") && method == Method::Get {
        return api::admin::test_http(req, env).await;
    }
    if path == "/admin/test/smtp" && method == Method::Post {
        return api::admin::test_smtp(req, env).await;
    }
    if path == "/admin/config" && method == Method::Post {
        return api::admin::save_config(req, env).await;
    }
    if path == "/admin/config/delete" && method == Method::Post {
        return api::admin::delete_config(req, env).await;
    }
    if path == "/admin/config/backup_db" && method == Method::Post {
        return api::admin::backup_db(req, env).await;
    }
    if path == "/admin/logout" && method == Method::Get {
        // Redirect back to admin login
        let mut resp = Response::ok("").map_err(|e| error::Error::internal(e.to_string()))?;
        let _ = resp.headers_mut().set("Location", "/admin");
        return Ok(resp.with_status(302));
    }
    if path.starts_with("/admin/users/by-mail/") {
        if let Some(email) = path_segment(path, "/admin/users/by-mail/", 0) {
            return api::admin::get_user_by_email(req, env, &email).await;
        }
    }
    if path.starts_with("/admin/organizations/") && path != "/admin/organizations/overview" {
        if let Some(org_id) = path_segment(path, "/admin/organizations/", 0) {
            let sub = path_segment(path, "/admin/organizations/", 1);
            if sub.as_deref() == Some("delete") && method == Method::Post {
                return api::admin::delete_organization(req, env, &org_id).await;
            }
        }
    }
    if path.starts_with("/admin/users/") {
        if let Some(user_id) = path_segment(path, "/admin/users/", 0) {
            if user_id != "overview" && user_id != "by-mail" && user_id != "update_revision" && user_id != "org_type" {
                let sub = path_segment(path, "/admin/users/", 1);
                match sub.as_deref() {
                    Some("delete") if method == Method::Post => {
                        return api::admin::delete_user(req, env, &user_id).await
                    }
                    Some("disable") if method == Method::Post => {
                        return api::admin::disable_user(req, env, &user_id).await
                    }
                    Some("enable") if method == Method::Post => {
                        return api::admin::enable_user(req, env, &user_id).await
                    }
                    Some("deauth") if method == Method::Post => {
                        return api::admin::deauth_user(req, env, &user_id).await
                    }
                    Some("remove-2fa") if method == Method::Post => {
                        return api::admin::remove_2fa(req, env, &user_id).await
                    }
                    Some("sso") if method == Method::Delete => return api::admin::delete_sso(req, env, &user_id).await,
                    Some("invite") => {
                        if path_segment(path, "/admin/users/", 2).as_deref() == Some("resend") && method == Method::Post
                        {
                            return api::admin::resend_invite(req, env, &user_id).await;
                        }
                    }
                    None if method == Method::Get => return api::admin::get_user(req, env, &user_id).await,
                    _ => {}
                }
            }
        }
    }

    // =========================================================================
    // Fallback: not found
    // =========================================================================
    Err(error::Error::not_found(format!("Route not found: {path}")))
}

/// Scheduled event handler for cleanup jobs (cron triggers).
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // Cleanup expired sends, trashed ciphers, etc.
    if let Ok(d1) = env.d1("DB") {
        let now = util::now_utc();

        // Purge sends past deletion date
        let _ = db::execute(&d1, "DELETE FROM sends WHERE deletion_date < ?1", &[db::val(&now)]).await;

        // Purge trashed ciphers older than 30 days
        let thirty_days_ago = chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::days(30))
            .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.6f").to_string())
            .unwrap_or_default();

        if !thirty_days_ago.is_empty() {
            // Delete related records for old trashed ciphers
            let _ = db::execute(
                &d1,
                "DELETE FROM folders_ciphers WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1)",
                &[db::val(&thirty_days_ago)],
            ).await;
            let _ = db::execute(
                &d1,
                "DELETE FROM favorites WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1)",
                &[db::val(&thirty_days_ago)],
            ).await;
            let _ = db::execute(
                &d1,
                "DELETE FROM ciphers_collections WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1)",
                &[db::val(&thirty_days_ago)],
            ).await;
            let _ = db::execute(
                &d1,
                "DELETE FROM attachments WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1)",
                &[db::val(&thirty_days_ago)],
            ).await;
            let _ = db::execute(
                &d1,
                "DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
                &[db::val(&thirty_days_ago)],
            )
            .await;
        }
    }
}
