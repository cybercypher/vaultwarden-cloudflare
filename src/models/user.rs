#![allow(dead_code)]
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::D1Database;

use crate::crypto;
use crate::db;
use crate::error::Result;
use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub uuid: String,
    pub enabled: i32,
    pub created_at: String,
    pub updated_at: String,
    pub verified_at: Option<String>,
    pub last_verifying_at: Option<String>,
    pub login_verify_count: i32,
    pub email: String,
    pub email_new: Option<String>,
    pub email_new_token: Option<String>,
    pub name: String,
    pub password_hash: String, // base64 encoded
    pub salt: String,          // base64 encoded
    pub password_iterations: i32,
    pub password_hint: Option<String>,
    pub akey: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_recover: Option<String>,
    pub security_stamp: String,
    pub stamp_exception: Option<String>,
    pub equivalent_domains: String,
    pub excluded_globals: String,
    pub client_kdf_type: i32,
    pub client_kdf_iter: i32,
    pub client_kdf_memory: Option<i32>,
    pub client_kdf_parallelism: Option<i32>,
    pub api_key: Option<String>,
    pub avatar_color: Option<String>,
    pub external_id: Option<String>,
}

impl User {
    pub fn new(email: String) -> Self {
        let now = util::now_utc();
        Self {
            uuid: util::get_uuid(),
            enabled: 1,
            created_at: now.clone(),
            updated_at: now,
            verified_at: None,
            last_verifying_at: None,
            login_verify_count: 0,
            email: email.to_lowercase(),
            email_new: None,
            email_new_token: None,
            name: String::new(),
            password_hash: String::new(),
            salt: String::new(),
            password_iterations: 600000,
            password_hint: None,
            akey: String::new(),
            private_key: None,
            public_key: None,
            totp_secret: None,
            totp_recover: None,
            security_stamp: util::get_uuid(),
            stamp_exception: None,
            equivalent_domains: "[]".to_string(),
            excluded_globals: "[]".to_string(),
            client_kdf_type: 0,
            client_kdf_iter: 600000,
            client_kdf_memory: None,
            client_kdf_parallelism: None,
            api_key: None,
            avatar_color: None,
            external_id: None,
        }
    }

    /// Set the user's password (server-side hashing of the client-provided hash).
    pub fn set_password(&mut self, master_password_hash: &str, password_hint: Option<String>, server_iterations: u32) {
        let salt = crypto::get_random_bytes::<64>();
        let hash = crypto::hash_password(master_password_hash.as_bytes(), &salt, server_iterations);

        self.password_hash = STANDARD.encode(&hash);
        self.salt = STANDARD.encode(&salt);
        self.password_iterations = server_iterations as i32;
        self.password_hint = password_hint;
    }

    /// Verify the master password hash.
    pub fn check_valid_password(&self, master_password_hash: &str) -> bool {
        let Ok(stored_hash) = STANDARD.decode(&self.password_hash) else {
            return false;
        };
        let Ok(salt) = STANDARD.decode(&self.salt) else {
            return false;
        };
        crypto::verify_password_hash(
            master_password_hash.as_bytes(),
            &salt,
            &stored_hash,
            self.password_iterations as u32,
        )
    }

    /// JSON representation for Bitwarden API profile response.
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "id": self.uuid,
            "name": self.name,
            "email": self.email,
            "emailVerified": self.verified_at.is_some(),
            "premium": true,
            "premiumFromOrganization": false,
            "masterPasswordHint": self.password_hint,
            "culture": "en-US",
            "twoFactorEnabled": false,
            "key": self.akey,
            "privateKey": self.private_key,
            "securityStamp": self.security_stamp,
            "forcePasswordReset": false,
            "usesKeyConnector": false,
            "avatarColor": self.avatar_color,
            "creationDate": util::format_date(&self.created_at),
            "organizations": [],
            "providers": [],
            "providerOrganizations": [],
            "object": "profile",
        })
    }

    // =========================================================================
    // D1 Database Operations
    // =========================================================================

    pub async fn save(&self, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "INSERT OR REPLACE INTO users (
                uuid, enabled, created_at, updated_at, verified_at, last_verifying_at,
                login_verify_count, email, email_new, email_new_token, name,
                password_hash, salt, password_iterations, password_hint,
                akey, private_key, public_key, totp_secret, totp_recover,
                security_stamp, stamp_exception, equivalent_domains, excluded_globals,
                client_kdf_type, client_kdf_iter, client_kdf_memory, client_kdf_parallelism,
                api_key, avatar_color, external_id
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31
            )",
            &[
                db::val(&self.uuid),
                db::val_i32(self.enabled),
                db::val(&self.created_at),
                db::val(&self.updated_at),
                db::val_opt(&self.verified_at),
                db::val_opt(&self.last_verifying_at),
                db::val_i32(self.login_verify_count),
                db::val(&self.email),
                db::val_opt(&self.email_new),
                db::val_opt(&self.email_new_token),
                db::val(&self.name),
                db::val(&self.password_hash),
                db::val(&self.salt),
                db::val_i32(self.password_iterations),
                db::val_opt(&self.password_hint),
                db::val(&self.akey),
                db::val_opt(&self.private_key),
                db::val_opt(&self.public_key),
                db::val_opt(&self.totp_secret),
                db::val_opt(&self.totp_recover),
                db::val(&self.security_stamp),
                db::val_opt(&self.stamp_exception),
                db::val(&self.equivalent_domains),
                db::val(&self.excluded_globals),
                db::val_i32(self.client_kdf_type),
                db::val_i32(self.client_kdf_iter),
                db::val_opt_i32(self.client_kdf_memory),
                db::val_opt_i32(self.client_kdf_parallelism),
                db::val_opt(&self.api_key),
                db::val_opt(&self.avatar_color),
                db::val_opt(&self.external_id),
            ],
        )
        .await
    }

    pub async fn find_by_uuid(uuid: &str, d1: &D1Database) -> Result<Option<User>> {
        db::query_one(d1, "SELECT * FROM users WHERE uuid = ?1", &[db::val(uuid)]).await
    }

    pub async fn find_by_email(email: &str, d1: &D1Database) -> Result<Option<User>> {
        db::query_one(d1, "SELECT * FROM users WHERE email = ?1", &[db::val(&email.to_lowercase())]).await
    }

    pub async fn delete(uuid: &str, d1: &D1Database) -> Result<()> {
        // Delete related records first
        for table in &["folders_ciphers", "favorites", "ciphers_collections"] {
            let query =
                format!("DELETE FROM {table} WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE user_uuid = ?1)");
            db::execute(d1, &query, &[db::val(uuid)]).await?;
        }
        for table in &["attachments"] {
            let query =
                format!("DELETE FROM {table} WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE user_uuid = ?1)");
            db::execute(d1, &query, &[db::val(uuid)]).await?;
        }
        // Delete invitations using a proper parameterized subquery
        db::execute(
            d1,
            "DELETE FROM invitations WHERE email IN (SELECT email FROM users WHERE uuid = ?1)",
            &[db::val(uuid)],
        )
        .await?;
        for table in &[
            "ciphers",
            "folders",
            "devices",
            "twofactor",
            "sends",
            "users_organizations",
            "users_collections",
            "emergency_access",
            "auth_requests",
            "twofactor_incomplete",
        ] {
            let col = if *table == "emergency_access" {
                "grantor_uuid"
            } else {
                "user_uuid"
            };
            let query = format!("DELETE FROM {table} WHERE {col} = ?1");
            let _ = db::execute(d1, &query, &[db::val(uuid)]).await;
        }
        // Also delete emergency access where user is grantee
        let _ = db::execute(d1, "DELETE FROM emergency_access WHERE grantee_uuid = ?1", &[db::val(uuid)]).await;
        db::execute(d1, "DELETE FROM users WHERE uuid = ?1", &[db::val(uuid)]).await
    }

    pub async fn update_revision(&self, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "UPDATE users SET updated_at = ?1 WHERE uuid = ?2",
            &[db::val(&util::now_utc()), db::val(&self.uuid)],
        )
        .await
    }
}
