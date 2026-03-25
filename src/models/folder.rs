#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::D1Database;

use crate::db;
use crate::error::Result;
use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub uuid: String,
    pub created_at: String,
    pub updated_at: String,
    pub user_uuid: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderCipher {
    pub cipher_uuid: String,
    pub folder_uuid: String,
}

impl Folder {
    pub fn new(user_uuid: String, name: String) -> Self {
        let now = util::now_utc();
        Self {
            uuid: util::get_uuid(),
            created_at: now.clone(),
            updated_at: now,
            user_uuid,
            name,
        }
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "id": self.uuid,
            "revisionDate": util::format_date(&self.updated_at),
            "name": self.name,
            "object": "folder",
        })
    }

    // =========================================================================
    // D1 Database Operations
    // =========================================================================

    pub async fn save(&mut self, d1: &D1Database) -> Result<()> {
        self.updated_at = util::now_utc();
        db::execute(
            d1,
            "INSERT OR REPLACE INTO folders (uuid, created_at, updated_at, user_uuid, name)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                db::val(&self.uuid),
                db::val(&self.created_at),
                db::val(&self.updated_at),
                db::val(&self.user_uuid),
                db::val(&self.name),
            ],
        )
        .await
    }

    pub async fn find_by_uuid(uuid: &str, d1: &D1Database) -> Result<Option<Folder>> {
        db::query_one(d1, "SELECT * FROM folders WHERE uuid = ?1", &[db::val(uuid)]).await
    }

    pub async fn find_by_user(user_uuid: &str, d1: &D1Database) -> Result<Vec<Folder>> {
        db::query_all(
            d1,
            "SELECT * FROM folders WHERE user_uuid = ?1",
            &[db::val(user_uuid)],
        )
        .await
    }

    pub async fn delete(uuid: &str, d1: &D1Database) -> Result<()> {
        db::execute(d1, "DELETE FROM folders_ciphers WHERE folder_uuid = ?1", &[db::val(uuid)]).await?;
        db::execute(d1, "DELETE FROM folders WHERE uuid = ?1", &[db::val(uuid)]).await
    }
}

impl FolderCipher {
    pub async fn save(cipher_uuid: &str, folder_uuid: &str, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "INSERT OR REPLACE INTO folders_ciphers (cipher_uuid, folder_uuid) VALUES (?1, ?2)",
            &[db::val(cipher_uuid), db::val(folder_uuid)],
        )
        .await
    }

    pub async fn delete(cipher_uuid: &str, folder_uuid: &str, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "DELETE FROM folders_ciphers WHERE cipher_uuid = ?1 AND folder_uuid = ?2",
            &[db::val(cipher_uuid), db::val(folder_uuid)],
        )
        .await
    }

    pub async fn delete_all_for_cipher(cipher_uuid: &str, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "DELETE FROM folders_ciphers WHERE cipher_uuid = ?1",
            &[db::val(cipher_uuid)],
        )
        .await
    }

    pub async fn find_folder_for_cipher(cipher_uuid: &str, user_uuid: &str, d1: &D1Database) -> Result<Option<String>> {
        let result: Option<FolderCipher> = db::query_one(
            d1,
            "SELECT fc.* FROM folders_ciphers fc
             INNER JOIN folders f ON f.uuid = fc.folder_uuid
             WHERE fc.cipher_uuid = ?1 AND f.user_uuid = ?2",
            &[db::val(cipher_uuid), db::val(user_uuid)],
        )
        .await?;
        Ok(result.map(|fc| fc.folder_uuid))
    }
}
