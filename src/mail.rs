#![allow(dead_code)]
//! Email sending module for Cloudflare Workers.
//!
//! Supports two backends:
//! 1. Cloudflare Email Workers `send_email` binding (free, requires Email Routing setup)
//! 2. HTTP API (Resend, SendGrid, Mailgun, etc.) via fetch
//!
//! Configure via wrangler.toml vars:
//!   MAIL_ENABLED = "true"
//!   MAIL_FROM = "vaultwarden@yourdomain.com"
//!   MAIL_FROM_NAME = "Vaultwarden"
//!   MAIL_BACKEND = "cloudflare" | "resend" | "sendgrid" | "smtp_bridge"
//!
//! For HTTP backends, set the API key as a secret:
//!   wrangler secret put MAIL_API_KEY

use base64::Engine;
use serde_json::json;
use wasm_bindgen::prelude::*;
use worker::Env;

use crate::error::{Error, Result};

/// Check if email sending is enabled.
pub fn is_enabled(env: &Env) -> bool {
    env.var("MAIL_ENABLED").map(|v| v.to_string() == "true").unwrap_or(false)
}

fn get_from(env: &Env) -> String {
    env.var("MAIL_FROM").map(|v| v.to_string()).unwrap_or_else(|_| "vaultwarden@example.com".to_string())
}

fn get_from_name(env: &Env) -> String {
    env.var("MAIL_FROM_NAME").map(|v| v.to_string()).unwrap_or_else(|_| "Vaultwarden".to_string())
}

fn get_backend(env: &Env) -> String {
    env.var("MAIL_BACKEND").map(|v| v.to_string()).unwrap_or_else(|_| "cloudflare".to_string())
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}

/// Send an email. Dispatches to the configured backend.
pub async fn send_email(env: &Env, to: &str, subject: &str, body_html: &str, body_text: &str) -> Result<()> {
    if !is_enabled(env) {
        return Ok(()); // Silently skip if email not configured
    }

    let backend = get_backend(env);
    match backend.as_str() {
        "cloudflare" => send_via_cloudflare(env, to, subject, body_html, body_text).await,
        "resend" => send_via_resend(env, to, subject, body_html, body_text).await,
        "sendgrid" => send_via_sendgrid(env, to, subject, body_html, body_text).await,
        "mailgun" => send_via_mailgun(env, to, subject, body_html, body_text).await,
        other => Err(Error::internal(format!("Unknown mail backend: {other}"))),
    }
}

// =============================================================================
// Cloudflare Email Workers backend (send_email binding)
// =============================================================================

/// Send email using Cloudflare's Email Workers send_email binding.
/// Requires Email Routing configured on the domain.
///
/// wrangler.toml:
/// ```toml
/// [[send_email]]
/// name = "SEND_EMAIL"
/// ```
async fn send_via_cloudflare(env: &Env, to: &str, subject: &str, body_html: &str, body_text: &str) -> Result<()> {
    let from = get_from(env);
    let from_name = get_from_name(env);

    // Build a MIME message
    let mime_message = build_mime_message(&from, &from_name, to, subject, body_html, body_text);

    // Access the send_email binding via JS interop
    let binding = env
        .var("__SEND_EMAIL_EXISTS") // Check if binding exists
        .ok();

    // Use the JS binding directly
    send_email_via_binding(env, &mime_message, &from, to).await
}

/// Call the Cloudflare send_email binding via JS interop.
async fn send_email_via_binding(env: &Env, mime_message: &str, from: &str, to: &str) -> Result<()> {
    // The send_email binding is accessed through the environment
    // We use wasm-bindgen to call the JS API
    let js_env: &JsValue = env.as_ref();

    let send_email_binding = js_sys::Reflect::get(js_env, &JsValue::from_str("SEND_EMAIL"))
        .map_err(|_| Error::internal("SEND_EMAIL binding not found. Add [[send_email]] to wrangler.toml"))?;

    if send_email_binding.is_undefined() || send_email_binding.is_null() {
        return Err(Error::internal("SEND_EMAIL binding not configured. Add [[send_email]] to wrangler.toml"));
    }

    // Create EmailMessage object
    let email_msg = create_email_message(from, to, mime_message)?;

    // Call send on the binding
    let send_fn = js_sys::Reflect::get(&send_email_binding, &JsValue::from_str("send"))
        .map_err(|_| Error::internal("send_email binding has no send method"))?;

    let send_fn: js_sys::Function = send_fn.dyn_into().map_err(|_| Error::internal("send is not a function"))?;

    let promise = send_fn
        .call1(&send_email_binding, &email_msg)
        .map_err(|e| Error::internal(format!("Email send failed: {e:?}")))?;

    let promise: js_sys::Promise = promise.dyn_into().map_err(|_| Error::internal("send did not return a promise"))?;

    wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map_err(|e| Error::internal(format!("Email send failed: {e:?}")))?;

    Ok(())
}

fn create_email_message(from: &str, to: &str, mime_content: &str) -> Result<JsValue> {
    // Create a JS object representing the email
    let msg = js_sys::Object::new();
    js_sys::Reflect::set(&msg, &"from".into(), &from.into()).map_err(|_| Error::internal("Failed to set from"))?;
    js_sys::Reflect::set(&msg, &"to".into(), &to.into()).map_err(|_| Error::internal("Failed to set to"))?;

    // Create raw MIME content as Uint8Array
    let content = mime_content.as_bytes();
    let array = js_sys::Uint8Array::new_with_length(content.len() as u32);
    array.copy_from(content);

    js_sys::Reflect::set(&msg, &"raw".into(), &array.into())
        .map_err(|_| Error::internal("Failed to set raw content"))?;

    Ok(msg.into())
}

// =============================================================================
// HTTP API backends
// =============================================================================

/// Send email via Resend (https://resend.com) - 100 emails/day free tier
async fn send_via_resend(env: &Env, to: &str, subject: &str, body_html: &str, _body_text: &str) -> Result<()> {
    let api_key = env
        .secret("MAIL_API_KEY")
        .map_err(|_| Error::internal("MAIL_API_KEY secret not set for Resend backend"))?
        .to_string();
    let from = get_from(env);
    let from_name = get_from_name(env);

    let payload = json!({
        "from": format!("{from_name} <{from}>"),
        "to": [to],
        "subject": subject,
        "html": body_html,
    });

    let mut headers = worker::Headers::new();
    headers.set("Authorization", &format!("Bearer {api_key}"))?;
    headers.set("Content-Type", "application/json")?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_headers(headers);
    init.with_body(Some(JsValue::from_str(&payload.to_string())));

    let request = worker::Request::new_with_init("https://api.resend.com/emails", &init)
        .map_err(|e| Error::internal(format!("Failed to create request: {e}")))?;

    let resp =
        worker::Fetch::Request(request).send().await.map_err(|e| Error::internal(format!("Resend API error: {e}")))?;

    if resp.status_code() >= 400 {
        return Err(Error::internal(format!("Resend API returned status {}", resp.status_code())));
    }

    Ok(())
}

/// Send email via SendGrid (https://sendgrid.com) - 100 emails/day free tier
async fn send_via_sendgrid(env: &Env, to: &str, subject: &str, body_html: &str, body_text: &str) -> Result<()> {
    let api_key = env
        .secret("MAIL_API_KEY")
        .map_err(|_| Error::internal("MAIL_API_KEY secret not set for SendGrid backend"))?
        .to_string();
    let from = get_from(env);
    let from_name = get_from_name(env);

    let payload = json!({
        "personalizations": [{
            "to": [{"email": to}]
        }],
        "from": {
            "email": from,
            "name": from_name
        },
        "subject": subject,
        "content": [
            {"type": "text/plain", "value": body_text},
            {"type": "text/html", "value": body_html}
        ]
    });

    let mut headers = worker::Headers::new();
    headers.set("Authorization", &format!("Bearer {api_key}"))?;
    headers.set("Content-Type", "application/json")?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_headers(headers);
    init.with_body(Some(JsValue::from_str(&payload.to_string())));

    let request = worker::Request::new_with_init("https://api.sendgrid.com/v3/mail/send", &init)
        .map_err(|e| Error::internal(format!("Failed to create request: {e}")))?;

    let resp = worker::Fetch::Request(request)
        .send()
        .await
        .map_err(|e| Error::internal(format!("SendGrid API error: {e}")))?;

    if resp.status_code() >= 400 {
        return Err(Error::internal(format!("SendGrid API returned status {}", resp.status_code())));
    }

    Ok(())
}

/// Send email via Mailgun (https://mailgun.com) - 100 emails/day for 3 months free
async fn send_via_mailgun(env: &Env, to: &str, subject: &str, body_html: &str, body_text: &str) -> Result<()> {
    let api_key = env
        .secret("MAIL_API_KEY")
        .map_err(|_| Error::internal("MAIL_API_KEY secret not set for Mailgun backend"))?
        .to_string();
    let domain = env
        .var("MAILGUN_DOMAIN")
        .map(|v| v.to_string())
        .map_err(|_| Error::internal("MAILGUN_DOMAIN variable not set"))?;
    let from = get_from(env);
    let from_name = get_from_name(env);

    let form_body = serde_urlencoded::to_string(&[
        ("from", format!("{from_name} <{from}>")),
        ("to", to.to_string()),
        ("subject", subject.to_string()),
        ("text", body_text.to_string()),
        ("html", body_html.to_string()),
    ])
    .map_err(|e| Error::internal(format!("Form encoding error: {e}")))?;

    let auth = base64::engine::general_purpose::STANDARD.encode(format!("api:{api_key}"));

    let mut headers = worker::Headers::new();
    headers.set("Authorization", &format!("Basic {auth}"))?;
    headers.set("Content-Type", "application/x-www-form-urlencoded")?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_headers(headers);
    init.with_body(Some(JsValue::from_str(&form_body)));

    let url = format!("https://api.mailgun.net/v3/{domain}/messages");
    let request = worker::Request::new_with_init(&url, &init)
        .map_err(|e| Error::internal(format!("Failed to create request: {e}")))?;

    let resp =
        worker::Fetch::Request(request).send().await.map_err(|e| Error::internal(format!("Mailgun API error: {e}")))?;

    if resp.status_code() >= 400 {
        return Err(Error::internal(format!("Mailgun API returned status {}", resp.status_code())));
    }

    Ok(())
}

// =============================================================================
// MIME message builder
// =============================================================================

fn build_mime_message(
    from: &str,
    from_name: &str,
    to: &str,
    subject: &str,
    body_html: &str,
    body_text: &str,
) -> String {
    let boundary = format!("----=_Part_{}", crate::util::get_uuid());
    format!(
        "From: {from_name} <{from}>\r\n\
         To: {to}\r\n\
         Subject: {subject}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\
         \r\n\
         {body_text}\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\
         \r\n\
         {body_html}\r\n\
         \r\n\
         --{boundary}--\r\n"
    )
}

// =============================================================================
// Email content builders (matching original vaultwarden email types)
// =============================================================================

/// Send password hint email.
pub async fn send_password_hint(env: &Env, to: &str, hint: Option<&str>) -> Result<()> {
    let domain = get_domain(env);
    let (subject, html, text) = if let Some(hint) = hint {
        (
            "Your Master Password Hint",
            format!(
                "<html><body>\
                 <p>You (or someone) recently requested your master password hint.</p>\
                 <p>Your hint is: <strong>{hint}</strong></p>\
                 <p>If you did not request this, you can safely ignore this email.</p>\
                 <p><em>{domain}</em></p>\
                 </body></html>"
            ),
            format!(
                "You (or someone) recently requested your master password hint.\n\n\
                 Your hint is: {hint}\n\n\
                 If you did not request this, you can safely ignore this email.\n\n\
                 {domain}"
            ),
        )
    } else {
        (
            "Your Master Password Hint",
            format!(
                "<html><body>\
                 <p>You (or someone) recently requested your master password hint.</p>\
                 <p>Unfortunately, your account does not have a password hint.</p>\
                 <p>If you did not request this, you can safely ignore this email.</p>\
                 <p><em>{domain}</em></p>\
                 </body></html>"
            ),
            format!(
                "You (or someone) recently requested your master password hint.\n\n\
                 Unfortunately, your account does not have a password hint.\n\n\
                 If you did not request this, you can safely ignore this email.\n\n\
                 {domain}"
            ),
        )
    };

    send_email(env, to, subject, &html, &text).await
}

/// Send email verification token.
pub async fn send_verify_email(env: &Env, to: &str, token: &str) -> Result<()> {
    let domain = get_domain(env);
    let subject = "Verify Your Email";
    let html = format!(
        "<html><body>\
         <p>Please verify your email address by clicking the link below:</p>\
         <p><a href=\"{domain}/#/verify-email/?userId=&token={token}\">Verify Email Address</a></p>\
         <p>If you did not create an account, you can safely ignore this email.</p>\
         <p><em>{domain}</em></p>\
         </body></html>"
    );
    let text = format!(
        "Please verify your email address.\n\n\
         Verification link: {domain}/#/verify-email/?userId=&token={token}\n\n\
         If you did not create an account, you can safely ignore this email.\n\n\
         {domain}"
    );

    send_email(env, to, subject, &html, &text).await
}

/// Send welcome email after registration.
pub async fn send_welcome(env: &Env, to: &str) -> Result<()> {
    let domain = get_domain(env);
    let subject = "Welcome to Vaultwarden";
    let html = format!(
        "<html><body>\
         <p>Welcome to Vaultwarden!</p>\
         <p>Your account has been created successfully.</p>\
         <p>You can access your vault at: <a href=\"{domain}\">{domain}</a></p>\
         </body></html>"
    );
    let text = format!(
        "Welcome to Vaultwarden!\n\n\
         Your account has been created successfully.\n\n\
         You can access your vault at: {domain}"
    );

    send_email(env, to, subject, &html, &text).await
}

/// Send 2FA email token.
pub async fn send_2fa_token(env: &Env, to: &str, token: &str) -> Result<()> {
    let domain = get_domain(env);
    let subject = "Vaultwarden Login Verification Code";
    let html = format!(
        "<html><body>\
         <p>Your two-step login verification code is: <strong>{token}</strong></p>\
         <p>If you did not request this code, you can safely ignore this email. \
         Someone may have entered your email address by mistake.</p>\
         <p><em>{domain}</em></p>\
         </body></html>"
    );
    let text = format!(
        "Your two-step login verification code is: {token}\n\n\
         If you did not request this code, you can safely ignore this email.\n\
         Someone may have entered your email address by mistake.\n\n\
         {domain}"
    );

    send_email(env, to, subject, &html, &text).await
}

/// Send incomplete 2FA login notification.
pub async fn send_incomplete_2fa_notification(
    env: &Env,
    to: &str,
    device_name: &str,
    ip_address: &str,
    login_time: &str,
) -> Result<()> {
    let domain = get_domain(env);
    let subject = "Incomplete Login Attempt";
    let html = format!(
        "<html><body>\
         <p>An incomplete login attempt was detected for your account.</p>\
         <p>Device: <strong>{device_name}</strong><br>\
         IP Address: <strong>{ip_address}</strong><br>\
         Time: <strong>{login_time}</strong></p>\
         <p>If this was you, your master password was entered correctly but the \
         second step of two-step login was not completed.</p>\
         <p>If this was not you, your master password may be compromised. \
         You should change it immediately.</p>\
         <p><em>{domain}</em></p>\
         </body></html>"
    );
    let text = format!(
        "An incomplete login attempt was detected for your account.\n\n\
         Device: {device_name}\n\
         IP Address: {ip_address}\n\
         Time: {login_time}\n\n\
         If this was you, your master password was entered correctly but the \
         second step of two-step login was not completed.\n\n\
         If this was not you, your master password may be compromised. \
         You should change it immediately.\n\n\
         {domain}"
    );

    send_email(env, to, subject, &html, &text).await
}

/// Send organization invite email.
pub async fn send_org_invite(
    env: &Env,
    to: &str,
    org_name: &str,
    invited_by: &str,
    token: &str,
    org_id: &str,
    member_id: &str,
) -> Result<()> {
    let domain = get_domain(env);
    let subject = &format!("Join {org_name} on Vaultwarden");
    let html = format!(
        "<html><body>\
         <p>{invited_by} has invited you to join the <strong>{org_name}</strong> organization.</p>\
         <p><a href=\"{domain}/#/accept-organization/?organizationId={org_id}&organizationUserId={member_id}&token={token}\">Accept Invitation</a></p>\
         <p><em>{domain}</em></p>\
         </body></html>"
    );
    let text = format!(
        "{invited_by} has invited you to join the {org_name} organization.\n\n\
         Accept invitation: {domain}/#/accept-organization/?organizationId={org_id}&organizationUserId={member_id}&token={token}\n\n\
         {domain}"
    );

    send_email(env, to, subject, &html, &text).await
}

/// Send account deletion confirmation email.
pub async fn send_delete_account(env: &Env, to: &str, token: &str) -> Result<()> {
    let domain = get_domain(env);
    let subject = "Delete Your Vaultwarden Account";
    let html = format!(
        "<html><body>\
         <p>A request to delete your account was made. To confirm, click the link below:</p>\
         <p><a href=\"{domain}/#/verify-recover-delete/?userId=&token={token}\">Delete Account</a></p>\
         <p>If you did not request this, you can safely ignore this email.</p>\
         <p><em>{domain}</em></p>\
         </body></html>"
    );
    let text = format!(
        "A request to delete your account was made.\n\n\
         To confirm: {domain}/#/verify-recover-delete/?userId=&token={token}\n\n\
         If you did not request this, you can safely ignore this email.\n\n\
         {domain}"
    );

    send_email(env, to, subject, &html, &text).await
}

/// Send email change verification.
pub async fn send_change_email(env: &Env, to: &str, token: &str) -> Result<()> {
    let domain = get_domain(env);
    let subject = "Change Your Email Address";
    let html = format!(
        "<html><body>\
         <p>A request to change your email address was made.</p>\
         <p>Your verification code is: <strong>{token}</strong></p>\
         <p>If you did not request this, you can safely ignore this email.</p>\
         <p><em>{domain}</em></p>\
         </body></html>"
    );
    let text = format!(
        "A request to change your email address was made.\n\n\
         Your verification code is: {token}\n\n\
         If you did not request this, you can safely ignore this email.\n\n\
         {domain}"
    );

    send_email(env, to, subject, &html, &text).await
}
