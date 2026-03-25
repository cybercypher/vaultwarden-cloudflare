#![allow(dead_code)]
use data_encoding::BASE64URL;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::D1Database;

use crate::crypto;
use crate::db;
use crate::error::Result;
use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub uuid: String,
    pub created_at: String,
    pub updated_at: String,
    pub user_uuid: String,
    pub name: String,
    pub atype: i32,
    pub push_uuid: Option<String>,
    pub push_token: Option<String>,
    pub refresh_token: String,
    pub twofactor_remember: Option<String>,
}

impl Device {
    pub fn new(uuid: String, user_uuid: String, name: String, atype: i32) -> Self {
        let now = util::now_utc();
        Self {
            uuid,
            created_at: now.clone(),
            updated_at: now,
            user_uuid,
            name,
            atype,
            push_uuid: Some(util::get_uuid()),
            push_token: None,
            refresh_token: crypto::encode_random_bytes::<64>(&BASE64URL),
            twofactor_remember: None,
        }
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "id": self.uuid,
            "name": self.name,
            "type": self.atype,
            "identifier": self.uuid,
            "creationDate": util::format_date(&self.created_at),
            "isTrusted": false,
            "object": "device",
        })
    }

    // Bitwarden device type to string
    pub fn type_to_string(atype: i32) -> String {
        match atype {
            0 => "Android",
            1 => "iOS",
            2 => "ChromeExtension",
            3 => "FirefoxExtension",
            4 => "OperaExtension",
            5 => "EdgeExtension",
            6 => "WindowsDesktop",
            7 => "MacOsDesktop",
            8 => "LinuxDesktop",
            9 => "ChromeBrowser",
            10 => "FirefoxBrowser",
            11 => "OperaBrowser",
            12 => "EdgeBrowser",
            13 => "IEBrowser",
            14 => "UnknownBrowser",
            15 => "AndroidAmazon",
            16 => "UWP",
            17 => "SafariBrowser",
            18 => "VivaldiBrowser",
            19 => "VivaldiExtension",
            20 => "SafariExtension",
            21 => "SDK",
            22 => "Server",
            23 => "WindowsCLI",
            24 => "MacOsCLI",
            25 => "LinuxCLI",
            _ => "Unknown",
        }
        .to_string()
    }

    // =========================================================================
    // D1 Database Operations
    // =========================================================================

    pub async fn save(&self, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "INSERT OR REPLACE INTO devices (
                uuid, created_at, updated_at, user_uuid, name, atype,
                push_uuid, push_token, refresh_token, twofactor_remember
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &[
                db::val(&self.uuid),
                db::val(&self.created_at),
                db::val(&self.updated_at),
                db::val(&self.user_uuid),
                db::val(&self.name),
                db::val_i32(self.atype),
                db::val_opt(&self.push_uuid),
                db::val_opt(&self.push_token),
                db::val(&self.refresh_token),
                db::val_opt(&self.twofactor_remember),
            ],
        )
        .await
    }

    pub async fn find_by_uuid_and_user(uuid: &str, user_uuid: &str, d1: &D1Database) -> Result<Option<Device>> {
        db::query_one(
            d1,
            "SELECT * FROM devices WHERE uuid = ?1 AND user_uuid = ?2",
            &[db::val(uuid), db::val(user_uuid)],
        )
        .await
    }

    pub async fn find_by_refresh_token(token: &str, d1: &D1Database) -> Result<Option<Device>> {
        db::query_one(d1, "SELECT * FROM devices WHERE refresh_token = ?1", &[db::val(token)]).await
    }

    pub async fn find_by_user(user_uuid: &str, d1: &D1Database) -> Result<Vec<Device>> {
        db::query_all(d1, "SELECT * FROM devices WHERE user_uuid = ?1", &[db::val(user_uuid)]).await
    }

    pub async fn delete_by_uuid_and_user(uuid: &str, user_uuid: &str, d1: &D1Database) -> Result<()> {
        db::execute(d1, "DELETE FROM devices WHERE uuid = ?1 AND user_uuid = ?2", &[db::val(uuid), db::val(user_uuid)])
            .await
    }
}
