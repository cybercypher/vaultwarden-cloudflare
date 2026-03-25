#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::D1Database;

use crate::db;
use crate::error::Result;
use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cipher {
    pub uuid: String,
    pub created_at: String,
    pub updated_at: String,
    pub user_uuid: Option<String>,
    pub organization_uuid: Option<String>,
    pub akey: Option<String>,
    pub atype: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<String>,
    pub data: String,
    pub password_history: Option<String>,
    pub deleted_at: Option<String>,
    pub reprompt: Option<i32>,
}

impl Cipher {
    pub fn new(atype: i32, name: String) -> Self {
        let now = util::now_utc();
        Self {
            uuid: util::get_uuid(),
            created_at: now.clone(),
            updated_at: now,
            user_uuid: None,
            organization_uuid: None,
            akey: None,
            atype,
            name,
            notes: None,
            fields: None,
            data: String::new(),
            password_history: None,
            deleted_at: None,
            reprompt: None,
        }
    }

    /// Convert cipher to Bitwarden API JSON response.
    /// `folder_id` and `favorite` are looked up separately per-user.
    pub fn to_json(
        &self,
        folder_id: Option<&str>,
        favorite: bool,
        attachments: &[Value],
    ) -> Value {
        // Parse the stored data JSON
        let data: Value = serde_json::from_str(&self.data).unwrap_or(Value::Null);
        let fields: Value = self
            .fields
            .as_ref()
            .and_then(|f| serde_json::from_str(f).ok())
            .unwrap_or(Value::Null);
        let password_history: Value = self
            .password_history
            .as_ref()
            .and_then(|p| serde_json::from_str(p).ok())
            .unwrap_or(Value::Null);

        let mut json = serde_json::json!({
            "id": self.uuid,
            "organizationId": self.organization_uuid,
            "folderId": folder_id,
            "type": self.atype,
            "name": self.name,
            "notes": self.notes,
            "fields": fields,
            "data": data,
            "favorite": favorite,
            "passwordHistory": password_history,
            "key": self.akey,
            "attachments": if attachments.is_empty() { Value::Null } else { Value::Array(attachments.to_vec()) },
            "organizationUseTotp": true,
            "revisionDate": util::format_date(&self.updated_at),
            "creationDate": util::format_date(&self.created_at),
            "deletedDate": self.deleted_at.as_ref().map(|d| util::format_date(d)),
            "reprompt": self.reprompt.unwrap_or(0),
            "collectionIds": [],
            "edit": true,
            "viewPassword": true,
            "object": "cipherDetails",
        });

        // Merge type-specific data at top level (Login, SecureNote, Card, Identity, SshKey)
        let type_key = match self.atype {
            1 => "login",
            2 => "secureNote",
            3 => "card",
            4 => "identity",
            5 => "sshKey",
            _ => "unknown",
        };
        json[type_key] = data.clone();

        json
    }

    // =========================================================================
    // D1 Database Operations
    // =========================================================================

    pub async fn save(&self, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "INSERT OR REPLACE INTO ciphers (
                uuid, created_at, updated_at, user_uuid, organization_uuid,
                akey, atype, name, notes, fields, data,
                password_history, deleted_at, reprompt
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            &[
                db::val(&self.uuid),
                db::val(&self.created_at),
                db::val(&self.updated_at),
                db::val_opt(&self.user_uuid),
                db::val_opt(&self.organization_uuid),
                db::val_opt(&self.akey),
                db::val_i32(self.atype),
                db::val(&self.name),
                db::val_opt(&self.notes),
                db::val_opt(&self.fields),
                db::val(&self.data),
                db::val_opt(&self.password_history),
                db::val_opt(&self.deleted_at),
                db::val_opt_i32(self.reprompt),
            ],
        )
        .await
    }

    pub async fn find_by_uuid(uuid: &str, d1: &D1Database) -> Result<Option<Cipher>> {
        db::query_one(d1, "SELECT * FROM ciphers WHERE uuid = ?1", &[db::val(uuid)]).await
    }

    /// Find all ciphers owned by a user (personal + org), including deleted.
    pub async fn find_by_user(user_uuid: &str, d1: &D1Database) -> Result<Vec<Cipher>> {
        db::query_all(
            d1,
            "SELECT c.* FROM ciphers c
             WHERE c.user_uuid = ?1
             UNION
             SELECT c.* FROM ciphers c
             INNER JOIN users_organizations uo ON c.organization_uuid = uo.org_uuid
             WHERE uo.user_uuid = ?1 AND uo.status = 2",
            &[db::val(user_uuid)],
        )
        .await
    }

    /// Find all non-deleted ciphers visible to a user (for list endpoints).
    pub async fn find_by_user_visible(user_uuid: &str, d1: &D1Database) -> Result<Vec<Cipher>> {
        db::query_all(
            d1,
            "SELECT c.* FROM ciphers c
             WHERE c.user_uuid = ?1 AND c.deleted_at IS NULL
             UNION
             SELECT c.* FROM ciphers c
             INNER JOIN users_organizations uo ON c.organization_uuid = uo.org_uuid
             WHERE uo.user_uuid = ?1 AND uo.status = 2 AND c.deleted_at IS NULL",
            &[db::val(user_uuid)],
        )
        .await
    }

    /// Find all ciphers in the user's trash.
    pub async fn find_deleted_by_user(user_uuid: &str, d1: &D1Database) -> Result<Vec<Cipher>> {
        db::query_all(
            d1,
            "SELECT * FROM ciphers WHERE user_uuid = ?1 AND deleted_at IS NOT NULL",
            &[db::val(user_uuid)],
        )
        .await
    }

    pub async fn soft_delete(uuid: &str, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE uuid = ?2",
            &[db::val(&util::now_utc()), db::val(uuid)],
        )
        .await
    }

    pub async fn restore(uuid: &str, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE uuid = ?2",
            &[db::val(&util::now_utc()), db::val(uuid)],
        )
        .await
    }

    pub async fn delete(uuid: &str, d1: &D1Database) -> Result<()> {
        // Delete related records
        db::execute(d1, "DELETE FROM folders_ciphers WHERE cipher_uuid = ?1", &[db::val(uuid)]).await?;
        db::execute(d1, "DELETE FROM ciphers_collections WHERE cipher_uuid = ?1", &[db::val(uuid)]).await?;
        db::execute(d1, "DELETE FROM favorites WHERE cipher_uuid = ?1", &[db::val(uuid)]).await?;
        db::execute(d1, "DELETE FROM attachments WHERE cipher_uuid = ?1", &[db::val(uuid)]).await?;
        db::execute(d1, "DELETE FROM ciphers WHERE uuid = ?1", &[db::val(uuid)]).await
    }

    /// Check if user owns this cipher directly (personal vault).
    pub fn is_owned_by_user(&self, user_uuid: &str) -> bool {
        self.user_uuid.as_deref() == Some(user_uuid)
    }

    /// Check if user owns or has organization access to this cipher.
    /// Must call with D1 for org membership lookup.
    pub async fn is_accessible_to_user(&self, user_uuid: &str, d1: &D1Database) -> crate::error::Result<bool> {
        // Personal cipher: direct ownership
        if self.user_uuid.as_deref() == Some(user_uuid) {
            return Ok(true);
        }
        // Organization cipher: check confirmed membership
        if let Some(org_uuid) = &self.organization_uuid {
            let member: Option<serde_json::Value> = crate::db::query_one(
                d1,
                "SELECT uuid FROM users_organizations WHERE user_uuid = ?1 AND org_uuid = ?2 AND status = 2",
                &[crate::db::val(user_uuid), crate::db::val(org_uuid)],
            ).await?;
            return Ok(member.is_some());
        }
        Ok(false)
    }
}

/// Favorite record
#[derive(Debug, Serialize, Deserialize)]
pub struct Favorite {
    pub user_uuid: String,
    pub cipher_uuid: String,
}

impl Favorite {
    pub async fn is_favorite(user_uuid: &str, cipher_uuid: &str, d1: &D1Database) -> Result<bool> {
        let result: Option<Favorite> = db::query_one(
            d1,
            "SELECT * FROM favorites WHERE user_uuid = ?1 AND cipher_uuid = ?2",
            &[db::val(user_uuid), db::val(cipher_uuid)],
        )
        .await?;
        Ok(result.is_some())
    }

    pub async fn set(user_uuid: &str, cipher_uuid: &str, favorite: bool, d1: &D1Database) -> Result<()> {
        if favorite {
            db::execute(
                d1,
                "INSERT OR IGNORE INTO favorites (user_uuid, cipher_uuid) VALUES (?1, ?2)",
                &[db::val(user_uuid), db::val(cipher_uuid)],
            )
            .await
        } else {
            db::execute(
                d1,
                "DELETE FROM favorites WHERE user_uuid = ?1 AND cipher_uuid = ?2",
                &[db::val(user_uuid), db::val(cipher_uuid)],
            )
            .await
        }
    }
}
