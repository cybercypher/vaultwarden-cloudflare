#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::D1Database;

use crate::db;
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub uuid: String,
    pub org_uuid: String,
    pub name: String,
    pub external_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionUser {
    pub user_uuid: String,
    pub collection_uuid: String,
    pub read_only: i32,
    pub hide_passwords: i32,
    pub manage: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionCipher {
    pub cipher_uuid: String,
    pub collection_uuid: String,
}

impl Collection {
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "id": self.uuid,
            "organizationId": self.org_uuid,
            "name": self.name,
            "externalId": self.external_id,
            "readOnly": false,
            "hidePasswords": false,
            "manage": false,
            "object": "collectionDetails",
        })
    }

    pub async fn find_by_user(user_uuid: &str, d1: &D1Database) -> Result<Vec<Collection>> {
        db::query_all(
            d1,
            "SELECT c.* FROM collections c
             INNER JOIN users_organizations uo ON c.org_uuid = uo.org_uuid
             WHERE uo.user_uuid = ?1 AND uo.status = 2",
            &[db::val(user_uuid)],
        )
        .await
    }

    pub async fn find_by_uuid(uuid: &str, d1: &D1Database) -> Result<Option<Collection>> {
        db::query_one(d1, "SELECT * FROM collections WHERE uuid = ?1", &[db::val(uuid)]).await
    }
}

impl CollectionCipher {
    pub async fn find_collections_for_cipher(cipher_uuid: &str, d1: &D1Database) -> Result<Vec<String>> {
        let results: Vec<CollectionCipher> = db::query_all(
            d1,
            "SELECT * FROM ciphers_collections WHERE cipher_uuid = ?1",
            &[db::val(cipher_uuid)],
        )
        .await?;
        Ok(results.into_iter().map(|cc| cc.collection_uuid).collect())
    }
}
