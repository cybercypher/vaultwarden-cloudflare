#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::D1Database;

use crate::db;
use crate::error::Result;
use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub uuid: String,
    pub name: String,
    pub billing_email: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    pub uuid: String,
    pub user_uuid: String,
    pub org_uuid: String,
    pub invited_by_email: Option<String>,
    pub access_all: i32,
    pub akey: String,
    pub status: i32,
    pub atype: i32,
    pub reset_password_key: Option<String>,
    pub external_id: Option<String>,
}

pub const MEMBERSHIP_INVITED: i32 = 0;
pub const MEMBERSHIP_ACCEPTED: i32 = 1;
pub const MEMBERSHIP_CONFIRMED: i32 = 2;

pub const MEMBERSHIP_OWNER: i32 = 0;
pub const MEMBERSHIP_ADMIN: i32 = 1;
pub const MEMBERSHIP_USER: i32 = 2;
pub const MEMBERSHIP_MANAGER: i32 = 3;

impl Organization {
    pub fn new(name: String, billing_email: String) -> Self {
        Self {
            uuid: util::get_uuid(),
            name,
            billing_email,
            private_key: None,
            public_key: None,
        }
    }

    pub fn to_json(&self, membership: &Membership) -> Value {
        serde_json::json!({
            "id": self.uuid,
            "identifier": Value::Null,
            "name": self.name,
            "seats": 10i32,
            "maxCollections": 10i32,
            "maxStorageGb": 10i32,
            "use2fa": true,
            "useDirectory": false,
            "useEvents": false,
            "useGroups": true,
            "useTotp": true,
            "usePolicies": true,
            "useApi": false,
            "useResetPassword": false,
            "useSso": false,
            "useKeyConnector": false,
            "selfHost": true,
            "hasPublicAndPrivateKeys": self.public_key.is_some() && self.private_key.is_some(),
            "resetPasswordEnrolled": false,
            "ssoBound": false,
            "usersGetPremium": true,
            "plan": "TeamsAnnually",
            "planType": 5i32,
            "type": membership.atype,
            "enabled": true,
            "status": membership.status,
            "providerId": Value::Null,
            "providerName": Value::Null,
            "providerType": Value::Null,
            "familySponsorshipFriendlyName": Value::Null,
            "familySponsorshipAvailable": false,
            "productTierType": 3i32,
            "keyConnectorEnabled": false,
            "keyConnectorUrl": Value::Null,
            "permissions": {
                "accessEventLogs": false,
                "accessImportExport": false,
                "accessReports": false,
                "createNewCollections": true,
                "editAnyCollection": true,
                "deleteAnyCollection": true,
                "editAssignedCollections": true,
                "deleteAssignedCollections": true,
                "manageGroups": false,
                "managePolicies": false,
                "manageSso": false,
                "manageUsers": false,
                "manageResetPassword": false,
                "manageScim": false
            },
            "userId": membership.user_uuid,
            "key": membership.akey,
            "object": "profileOrganization",
        })
    }

    pub async fn save(&self, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "INSERT OR REPLACE INTO organizations (uuid, name, billing_email, private_key, public_key)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                db::val(&self.uuid),
                db::val(&self.name),
                db::val(&self.billing_email),
                db::val_opt(&self.private_key),
                db::val_opt(&self.public_key),
            ],
        )
        .await
    }

    pub async fn find_by_uuid(uuid: &str, d1: &D1Database) -> Result<Option<Organization>> {
        db::query_one(d1, "SELECT * FROM organizations WHERE uuid = ?1", &[db::val(uuid)]).await
    }
}

impl Membership {
    pub async fn find_by_user(user_uuid: &str, d1: &D1Database) -> Result<Vec<Membership>> {
        db::query_all(
            d1,
            "SELECT * FROM users_organizations WHERE user_uuid = ?1",
            &[db::val(user_uuid)],
        )
        .await
    }

    pub async fn find_confirmed_by_user(user_uuid: &str, d1: &D1Database) -> Result<Vec<Membership>> {
        db::query_all(
            d1,
            "SELECT * FROM users_organizations WHERE user_uuid = ?1 AND status = ?2",
            &[db::val(user_uuid), db::val_i32(MEMBERSHIP_CONFIRMED)],
        )
        .await
    }

    pub async fn save(&self, d1: &D1Database) -> Result<()> {
        db::execute(
            d1,
            "INSERT OR REPLACE INTO users_organizations (
                uuid, user_uuid, org_uuid, invited_by_email, access_all,
                akey, status, atype, reset_password_key, external_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &[
                db::val(&self.uuid),
                db::val(&self.user_uuid),
                db::val(&self.org_uuid),
                db::val_opt(&self.invited_by_email),
                db::val_i32(self.access_all),
                db::val(&self.akey),
                db::val_i32(self.status),
                db::val_i32(self.atype),
                db::val_opt(&self.reset_password_key),
                db::val_opt(&self.external_id),
            ],
        )
        .await
    }
}
