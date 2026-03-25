#![allow(dead_code)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use signature::{SignatureEncoding, Signer, Verifier};
use worker::Env;

use crate::error::{Error, Result};

const JWT_HEADER_B64: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
// = base64url({"alg":"RS256","typ":"JWT"})

/// Load RSA private key from Cloudflare secret.
/// Handles both literal newlines and escaped \n in the PEM string,
/// and both PKCS#1 (BEGIN RSA PRIVATE KEY) and PKCS#8 (BEGIN PRIVATE KEY) formats.
fn get_private_key(env: &Env) -> Result<RsaPrivateKey> {
    let raw_pem = env
        .secret("RSA_PRIVATE_KEY_PEM")
        .map_err(|_| Error::internal("RSA_PRIVATE_KEY_PEM secret not set"))?
        .to_string();
    // Handle escaped newlines from environment variables
    let pem = raw_pem.replace("\\n", "\n");

    // Try PKCS#8 first, then PKCS#1
    RsaPrivateKey::from_pkcs8_pem(&pem)
        .or_else(|_| {
            use rsa::pkcs1::DecodeRsaPrivateKey;
            RsaPrivateKey::from_pkcs1_pem(&pem)
        })
        .map_err(|e| Error::internal(format!("Invalid RSA key: {e}")))
}

/// Encode a JWT with RS256.
pub fn encode_jwt<T: Serialize>(claims: &T, env: &Env) -> Result<String> {
    let private_key = get_private_key(env)?;
    let signing_key = SigningKey::<Sha256>::new(private_key);

    let payload = serde_json::to_vec(claims).map_err(|e| Error::internal(format!("JWT serialize: {e}")))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
    let signing_input = format!("{JWT_HEADER_B64}.{payload_b64}");

    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Decode and verify a JWT with RS256.
pub fn decode_jwt<T: DeserializeOwned>(token: &str, issuer: &str, env: &Env) -> Result<T> {
    let private_key = get_private_key(env)?;
    let public_key = RsaPublicKey::from(&private_key);
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    let token = token.replace(char::is_whitespace, "");
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::unauthorized("Invalid token format"));
    }

    // Verify signature
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| Error::unauthorized("Invalid token signature encoding"))?;
    let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| Error::unauthorized("Invalid signature"))?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| Error::unauthorized("Token signature verification failed"))?;

    // Decode payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| Error::unauthorized("Invalid token payload encoding"))?;
    let claims: T =
        serde_json::from_slice(&payload_bytes).map_err(|_| Error::unauthorized("Invalid token payload"))?;

    // Verify header matches expected RS256
    if parts[0] != JWT_HEADER_B64 {
        return Err(Error::unauthorized("Invalid token algorithm"));
    }

    // Verify issuer and expiration (mandatory)
    let raw: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| Error::unauthorized("Invalid token payload structure"))?;
    let iss = raw.get("iss").and_then(|v| v.as_str())
        .ok_or_else(|| Error::unauthorized("Token missing issuer"))?;
    if iss != issuer {
        return Err(Error::unauthorized("Invalid token issuer"));
    }
    let exp = raw.get("exp").and_then(|v| v.as_i64())
        .ok_or_else(|| Error::unauthorized("Token missing expiration"))?;
    if exp < chrono::Utc::now().timestamp() {
        return Err(Error::unauthorized("Token has expired"));
    }

    Ok(claims)
}

// ============================================================================
// JWT Claims Structs
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginJwtClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String, // user UUID
    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub sstamp: String,    // security stamp
    pub device: String,    // device UUID
    pub devicetype: String,
    pub client_id: String,
    pub scope: Vec<String>,
    pub amr: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshJwtClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub device: String,
    pub token: String, // refresh token identifier
    pub scope: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorRememberClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub device: String,
}

/// Create login JWT claims.
pub fn make_login_claims(
    user_uuid: &str,
    email: &str,
    name: &str,
    device_uuid: &str,
    device_type: &str,
    security_stamp: &str,
    client_id: &str,
    scope: Vec<String>,
    access_validity_secs: i64,
    domain: &str,
) -> LoginJwtClaims {
    let now = chrono::Utc::now().timestamp();
    LoginJwtClaims {
        nbf: now,
        exp: now + access_validity_secs,
        iss: format!("{domain}|login"),
        sub: user_uuid.to_string(),
        premium: true,
        name: name.to_string(),
        email: email.to_string(),
        email_verified: true,
        sstamp: security_stamp.to_string(),
        device: device_uuid.to_string(),
        devicetype: device_type.to_string(),
        client_id: client_id.to_string(),
        scope,
        amr: vec!["Application".into()],
    }
}

/// Create refresh JWT claims.
pub fn make_refresh_claims(
    user_uuid: &str,
    device_uuid: &str,
    refresh_token: &str,
    scope: Vec<String>,
    refresh_validity_days: i64,
    domain: &str,
) -> RefreshJwtClaims {
    let now = chrono::Utc::now().timestamp();
    RefreshJwtClaims {
        nbf: now,
        exp: now + refresh_validity_days * 86400,
        iss: format!("{domain}|login"),
        sub: user_uuid.to_string(),
        device: device_uuid.to_string(),
        token: refresh_token.to_string(),
        scope,
    }
}

/// Decode a login access token.
pub fn decode_login(token: &str, domain: &str, env: &Env) -> Result<LoginJwtClaims> {
    let issuer = format!("{domain}|login");
    decode_jwt(token, &issuer, env)
}

/// Decode a refresh token.
pub fn decode_refresh(token: &str, domain: &str, env: &Env) -> Result<RefreshJwtClaims> {
    let issuer = format!("{domain}|login");
    decode_jwt(token, &issuer, env)
}

/// Extract user UUID from a Bearer token in the request.
pub fn get_auth_user(req: &worker::Request, domain: &str, env: &Env) -> Result<LoginJwtClaims> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .map_err(|_| Error::unauthorized("Missing Authorization header"))?
        .ok_or_else(|| Error::unauthorized("Missing Authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| Error::unauthorized("Invalid Authorization header format"))?;

    decode_login(token, domain, env)
}

/// Validate that the security stamp in the JWT matches the user's current stamp.
/// Call this after get_auth_user when you need to ensure the token hasn't been
/// invalidated by a password change or security stamp rotation.
pub async fn validate_security_stamp(
    claims: &LoginJwtClaims,
    d1: &worker::D1Database,
) -> Result<()> {
    let user: Option<crate::models::User> = crate::db::query_one(
        d1,
        "SELECT * FROM users WHERE uuid = ?1",
        &[crate::db::val(&claims.sub)],
    )
    .await?;

    let user = user.ok_or_else(|| Error::unauthorized("User not found"))?;

    if user.security_stamp != claims.sstamp {
        return Err(Error::unauthorized(
            "Token has been invalidated. Please login again.",
        ));
    }
    Ok(())
}
