#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::D1Database;

use crate::db;
use crate::error::Result;
use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Send {
    pub uuid: String,
    pub user_uuid: Option<String>,
    pub organization_uuid: Option<String>,
    pub name: String,
    pub notes: Option<String>,
    pub atype: i32,
    pub data: String,
    pub akey: String,
    pub password_hash: Option<String>,
    pub password_salt: Option<String>,
    pub password_iter: Option<i32>,
    pub max_access_count: Option<i32>,
    pub access_count: i32,
    pub creation_date: String,
    pub revision_date: String,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub disabled: i32,
    pub hide_email: Option<i32>,
}

impl Send {
    pub fn to_json(&self) -> Value {
        let data: Value = serde_json::from_str(&self.data).unwrap_or(Value::Null);
        serde_json::json!({
            "id": self.uuid,
            "accessId": self.uuid,
            "type": self.atype,
            "name": self.name,
            "notes": self.notes,
            "key": self.akey,
            "maxAccessCount": self.max_access_count,
            "accessCount": self.access_count,
            "password": self.password_hash.as_ref().map(|_| ""),
            "disabled": self.disabled != 0,
            "hideEmail": self.hide_email.map(|h| h != 0).unwrap_or(false),
            "revisionDate": util::format_date(&self.revision_date),
            "expirationDate": self.expiration_date.as_ref().map(|d| util::format_date(d)),
            "deletionDate": util::format_date(&self.deletion_date),
            "data": data,
            "object": "send",
        })
    }

    pub async fn find_by_user(user_uuid: &str, d1: &D1Database) -> Result<Vec<Send>> {
        db::query_all(
            d1,
            "SELECT * FROM sends WHERE user_uuid = ?1",
            &[db::val(user_uuid)],
        )
        .await
    }

    pub async fn save(&self, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "INSERT OR REPLACE INTO sends (
                uuid, user_uuid, organization_uuid, name, notes, atype, data, akey,
                password_hash, password_salt, password_iter, max_access_count,
                access_count, creation_date, revision_date, expiration_date,
                deletion_date, disabled, hide_email
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
            &[
                db::val(&self.uuid),
                db::val_opt(&self.user_uuid),
                db::val_opt(&self.organization_uuid),
                db::val(&self.name),
                db::val_opt(&self.notes),
                db::val_i32(self.atype),
                db::val(&self.data),
                db::val(&self.akey),
                db::val_opt(&self.password_hash),
                db::val_opt(&self.password_salt),
                db::val_opt_i32(self.password_iter),
                db::val_opt_i32(self.max_access_count),
                db::val_i32(self.access_count),
                db::val(&self.creation_date),
                db::val(&self.revision_date),
                db::val_opt(&self.expiration_date),
                db::val(&self.deletion_date),
                db::val_i32(self.disabled),
                db::val_opt_i32(self.hide_email),
            ],
        )
        .await
    }

    pub async fn find_by_uuid(uuid: &str, d1: &D1Database) -> Result<Option<Send>> {
        db::query_one(d1, "SELECT * FROM sends WHERE uuid = ?1", &[db::val(uuid)]).await
    }

    pub async fn delete(uuid: &str, d1: &D1Database) -> Result<()> {
        db::execute(d1, "DELETE FROM sends WHERE uuid = ?1", &[db::val(uuid)]).await
    }

    pub async fn purge_expired(d1: &D1Database) -> Result<()> {
        let now = crate::util::now_utc();
        db::execute(d1, "DELETE FROM sends WHERE deletion_date < ?1", &[db::val(&now)]).await
    }
}
