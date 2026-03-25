#![allow(dead_code)]
//! WebSocket push notifications via Cloudflare Durable Objects.
//!
//! Uses the Hibernatable WebSocket API for zero-cost idle connections.
//! Bitwarden clients connect via SignalR MessagePack protocol.

use rmpv::Value as MpValue;
use worker::*;

// SignalR protocol constants
const RECORD_SEPARATOR: u8 = 0x1e;
const INITIAL_RESPONSE: [u8; 3] = [0x7b, 0x7d, RECORD_SEPARATOR]; // {}\x1e

/// Update types matching Bitwarden SignalR protocol
#[derive(Clone, Copy)]
#[repr(i32)]
pub enum UpdateType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,
    SyncVault = 5,
    SyncOrgKeys = 6,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncSettings = 10,
    LogOut = 11,
    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,
    AuthRequest = 15,
    AuthRequestResponse = 16,
}

/// Create a SignalR MessagePack notification payload.
pub fn create_update(
    ut: UpdateType,
    payload: Vec<(MpValue, MpValue)>,
    acting_device_id: Option<&str>,
) -> Vec<u8> {
    let value = MpValue::Array(vec![
        1.into(),
        MpValue::Map(vec![]),
        MpValue::Nil,
        "ReceiveMessage".into(),
        MpValue::Array(vec![MpValue::Map(vec![
            (
                "ContextId".into(),
                acting_device_id
                    .map(|v| MpValue::String(v.into()))
                    .unwrap_or(MpValue::Nil),
            ),
            ("Type".into(), (ut as i32).into()),
            ("Payload".into(), MpValue::Map(payload)),
        ])]),
    ]);

    serialize_msgpack(&value)
}

fn serialize_msgpack(val: &MpValue) -> Vec<u8> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, val).expect("Error encoding MsgPack");

    // Add SignalR BinaryMessageFormat size prefix
    let mut size: usize = buf.len();
    let mut len_buf: Vec<u8> = Vec::new();
    loop {
        let mut size_part = size & 0x7f;
        size >>= 7;
        if size > 0 {
            size_part |= 0x80;
        }
        len_buf.push(size_part as u8);
        if size == 0 {
            break;
        }
    }

    len_buf.append(&mut buf);
    len_buf
}

/// Build payload for cipher updates
pub fn cipher_update_payload(cipher_id: &str, user_id: &str, org_id: Option<&str>, revision_date: &str) -> Vec<(MpValue, MpValue)> {
    let mut payload = vec![
        ("Id".into(), MpValue::String(cipher_id.into())),
        ("UserId".into(), MpValue::String(user_id.into())),
        ("RevisionDate".into(), MpValue::String(revision_date.into())),
    ];
    if let Some(oid) = org_id {
        payload.push(("OrganizationId".into(), MpValue::String(oid.into())));
    }
    payload
}

/// Build payload for folder updates
pub fn folder_update_payload(folder_id: &str, user_id: &str, revision_date: &str) -> Vec<(MpValue, MpValue)> {
    vec![
        ("Id".into(), MpValue::String(folder_id.into())),
        ("UserId".into(), MpValue::String(user_id.into())),
        ("RevisionDate".into(), MpValue::String(revision_date.into())),
    ]
}

/// Build payload for send updates

/// Build payload for user-level updates (logout, settings, etc.)
pub fn user_update_payload(user_id: &str, _date: &str) -> Vec<(MpValue, MpValue)> {
    vec![
        ("UserId".into(), MpValue::String(user_id.into())),
        ("Date".into(), MpValue::String(_date.into())),
    ]
}

// =============================================================================
// Durable Object: NotificationHub
// =============================================================================

/// The Durable Object that manages WebSocket connections for a single user.
/// One DO instance per user - identified by user UUID.
#[durable_object]
pub struct NotificationHub {
    state: State,
    env: Env,
}

impl DurableObject for NotificationHub {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let req_url = req.url()?;
        let path = req_url.path();

        if path.ends_with("/ws") {
            let pair = WebSocketPair::new()?;
            let server = pair.server;
            let client = pair.client;

            self.state.accept_websocket_with_tags(&server, &["user"]);

            Response::from_websocket(client)
        } else if path.ends_with("/notify") {
            let mut req = req;
            let body = req.bytes().await?;
            let websockets = self.state.get_websockets_with_tag("user");

            for ws in websockets {
                let _ = ws.send_with_bytes(&body);
            }

            Response::ok("sent")
        } else {
            Response::error("Not found", 404)
        }
    }

    async fn websocket_message(&self, ws: WebSocket, message: WebSocketIncomingMessage) -> Result<()> {
        match message {
            WebSocketIncomingMessage::String(text) => {
                // Handle SignalR initial handshake
                let msg = text.trim_end_matches(RECORD_SEPARATOR as char);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(msg) {
                    if val.get("protocol").and_then(|p| p.as_str()) == Some("messagepack") {
                        let _ = ws.send_with_bytes(&INITIAL_RESPONSE);
                    }
                }
            }
            WebSocketIncomingMessage::Binary(_) => {
                // Binary messages from client are typically pings - ignore
            }
        }
        Ok(())
    }

    /// Handle WebSocket close
    async fn websocket_close(&self, _ws: WebSocket, _code: usize, _reason: String, _was_clean: bool) -> Result<()> {
        // The runtime automatically cleans up closed sockets from get_websockets()
        Ok(())
    }

    /// Handle WebSocket error
    async fn websocket_error(&self, _ws: WebSocket, _error: Error) -> Result<()> {
        Ok(())
    }
}

// =============================================================================
// Helper: Send notification to a user's DO from the Worker
// =============================================================================

/// Send a push notification to a specific user by forwarding to their Durable Object.
pub async fn send_notification(
    env: &Env,
    user_uuid: &str,
    message: &[u8],
) -> crate::error::Result<()> {
    let namespace = env
        .durable_object("NOTIFICATION_HUB")
        .map_err(|e| crate::error::Error::internal(format!("DO binding error: {e}")))?;

    let stub = namespace
        .id_from_name(user_uuid)
        .map_err(|e| crate::error::Error::internal(format!("DO id error: {e}")))?
        .get_stub()
        .map_err(|e| crate::error::Error::internal(format!("DO stub error: {e}")))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(wasm_bindgen::JsValue::from(js_sys::Uint8Array::from(message))));

    let req = Request::new_with_init(
        &format!("https://do-internal/notify"),
        &init,
    )
    .map_err(|e| crate::error::Error::internal(format!("DO request error: {e}")))?;

    let _ = stub.fetch_with_request(req).await;
    Ok(())
}

/// Convenience: send a cipher update notification
pub async fn notify_cipher_update(
    env: &Env,
    ut: UpdateType,
    cipher_id: &str,
    user_id: &str,
    org_id: Option<&str>,
    acting_device_id: Option<&str>,
) {
    let now = crate::util::now_utc();
    let payload = cipher_update_payload(cipher_id, user_id, org_id, &now);
    let msg = create_update(ut, payload, acting_device_id);
    let _ = send_notification(env, user_id, &msg).await;

    // If org cipher, notify all org members
    if let Some(oid) = org_id {
        if let Ok(d1) = env.d1("DB") {
            #[derive(serde::Deserialize)]
            struct Member { user_uuid: String }
            if let Ok(members) = crate::db::query_all::<Member>(
                &d1,
                "SELECT user_uuid FROM users_organizations WHERE org_uuid = ?1 AND status = 2",
                &[crate::db::val(oid)],
            ).await {
                for m in members {
                    if m.user_uuid != user_id {
                        let msg = create_update(ut, cipher_update_payload(cipher_id, &m.user_uuid, Some(oid), &now), acting_device_id);
                        let _ = send_notification(env, &m.user_uuid, &msg).await;
                    }
                }
            }
        }
    }
}

/// Convenience: send a folder update notification
pub async fn notify_folder_update(
    env: &Env,
    ut: UpdateType,
    folder_id: &str,
    user_id: &str,
    acting_device_id: Option<&str>,
) {
    let payload = folder_update_payload(folder_id, user_id, &crate::util::now_utc());
    let msg = create_update(ut, payload, acting_device_id);
    let _ = send_notification(env, user_id, &msg).await;
}

/// Convenience: send a send update notification

/// Convenience: send logout notification to a user
pub async fn notify_logout(env: &Env, user_id: &str, acting_device_id: Option<&str>) {
    let payload = user_update_payload(user_id, &crate::util::now_utc());
    let msg = create_update(UpdateType::LogOut, payload, acting_device_id);
    let _ = send_notification(env, user_id, &msg).await;
}
