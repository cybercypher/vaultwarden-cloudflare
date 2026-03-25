use serde_json::{json, Value};
use worker::{Env, Request, Response};

use crate::auth;
use crate::db;
use crate::error::{Error, Result};
use crate::models::collection::Collection;
use crate::models::organization::{
    Membership, Organization, MEMBERSHIP_CONFIRMED, MEMBERSHIP_INVITED, MEMBERSHIP_OWNER, MEMBERSHIP_USER,
};
use crate::util;

/// POST /api/organizations
pub async fn create(mut req: Request, env: &Env) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let name = body["name"].as_str().ok_or_else(|| Error::bad_request("name required"))?;
    let billing_email = body["billingEmail"].as_str().unwrap_or(&claims.email);

    let org = Organization::new(name.to_string(), billing_email.to_string());

    // Set org keys if provided
    let mut org = org;
    if let Some(key) = body["key"].as_str() {
        // keys are provided during org creation
        if let Some(keys) = body.get("keys") {
            org.public_key = keys["publicKey"].as_str().map(|s| s.to_string());
            org.private_key = keys["encryptedPrivateKey"].as_str().map(|s| s.to_string());
        }

        org.save(&d1).await?;

        // Create owner membership
        let membership = Membership {
            uuid: util::get_uuid(),
            user_uuid: claims.sub.clone(),
            org_uuid: org.uuid.clone(),
            invited_by_email: None,
            access_all: 1,
            akey: key.to_string(),
            status: MEMBERSHIP_CONFIRMED,
            atype: MEMBERSHIP_OWNER,
            reset_password_key: None,
            external_id: None,
        };
        membership.save(&d1).await?;
    } else {
        org.save(&d1).await?;
    }

    // Build response
    let membership = Membership {
        uuid: util::get_uuid(),
        user_uuid: claims.sub.clone(),
        org_uuid: org.uuid.clone(),
        invited_by_email: None,
        access_all: 1,
        akey: body["key"].as_str().unwrap_or("").to_string(),
        status: MEMBERSHIP_CONFIRMED,
        atype: MEMBERSHIP_OWNER,
        reset_password_key: None,
        external_id: None,
    };

    Response::from_json(&org.to_json(&membership)).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/organizations/:org_id
pub async fn get_org(req: Request, env: &Env, org_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let org =
        Organization::find_by_uuid(org_id, &d1).await?.ok_or_else(|| Error::not_found("Organization not found"))?;
    let membership = require_membership(&claims.sub, org_id, &d1).await?;

    Response::from_json(&org.to_json(&membership)).map_err(|e| Error::internal(e.to_string()))
}

/// DELETE /api/organizations/:org_id
pub async fn delete_org(mut req: Request, env: &Env, org_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let membership = require_membership(&claims.sub, org_id, &d1).await?;
    if membership.atype != MEMBERSHIP_OWNER {
        return Err(Error::unauthorized("Only owners can delete organizations"));
    }

    // Verify password (mandatory)
    let body: Value = req.json().await.unwrap_or(json!({}));
    let hash =
        body["masterPasswordHash"].as_str().ok_or_else(|| Error::bad_request("masterPasswordHash is required"))?;
    {
        let user = crate::models::User::find_by_uuid(&claims.sub, &d1)
            .await?
            .ok_or_else(|| Error::not_found("User not found"))?;
        if !user.check_valid_password(hash) {
            return Err(Error::bad_request("Invalid password"));
        }
    }

    // Delete all org data
    db::execute(
        &d1,
        "DELETE FROM ciphers_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        &[db::val(org_id)],
    )
    .await?;
    db::execute(
        &d1,
        "DELETE FROM users_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        &[db::val(org_id)],
    )
    .await?;
    db::execute(
        &d1,
        "DELETE FROM collections_groups WHERE collections_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        &[db::val(org_id)],
    )
    .await?;
    db::execute(&d1, "DELETE FROM collections WHERE org_uuid = ?1", &[db::val(org_id)]).await?;
    db::execute(
        &d1,
        "DELETE FROM groups_users WHERE groups_uuid IN (SELECT uuid FROM groups WHERE organizations_uuid = ?1)",
        &[db::val(org_id)],
    )
    .await?;
    db::execute(&d1, "DELETE FROM groups WHERE organizations_uuid = ?1", &[db::val(org_id)]).await?;
    db::execute(&d1, "DELETE FROM org_policies WHERE org_uuid = ?1", &[db::val(org_id)]).await?;
    db::execute(&d1, "DELETE FROM ciphers WHERE organization_uuid = ?1", &[db::val(org_id)]).await?;
    db::execute(&d1, "DELETE FROM users_organizations WHERE org_uuid = ?1", &[db::val(org_id)]).await?;
    db::execute(&d1, "DELETE FROM organization_api_key WHERE org_uuid = ?1", &[db::val(org_id)]).await?;
    db::execute(&d1, "DELETE FROM organizations WHERE uuid = ?1", &[db::val(org_id)]).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/organizations/:org_id/leave
pub async fn leave(req: Request, env: &Env, org_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let membership = require_membership(&claims.sub, org_id, &d1).await?;

    // Don't allow last owner to leave
    if membership.atype == MEMBERSHIP_OWNER {
        let owners: Vec<Membership> = db::query_all(
            &d1,
            "SELECT * FROM users_organizations WHERE org_uuid = ?1 AND atype = 0 AND status = 2",
            &[db::val(org_id)],
        )
        .await?;
        if owners.len() <= 1 {
            return Err(Error::bad_request("Cannot leave as the only owner"));
        }
    }

    db::execute(&d1, "DELETE FROM users_organizations WHERE uuid = ?1", &[db::val(&membership.uuid)]).await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/organizations/:org_id/users
pub async fn get_members(req: Request, env: &Env, org_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let _membership = require_membership(&claims.sub, org_id, &d1).await?;

    let members: Vec<Membership> =
        db::query_all(&d1, "SELECT * FROM users_organizations WHERE org_uuid = ?1", &[db::val(org_id)]).await?;

    let mut member_list = Vec::new();
    for m in &members {
        let user = crate::models::User::find_by_uuid(&m.user_uuid, &d1).await?;
        let name = user.as_ref().map(|u| u.name.as_str()).unwrap_or("");
        let email = user.as_ref().map(|u| u.email.as_str()).unwrap_or("");

        member_list.push(json!({
            "id": m.uuid,
            "userId": m.user_uuid,
            "name": name,
            "email": email,
            "type": m.atype,
            "status": m.status,
            "accessAll": m.access_all != 0,
            "twoFactorEnabled": false,
            "resetPasswordEnrolled": false,
            "object": "organizationUserUserDetails",
            "collections": [],
            "groups": [],
        }));
    }

    let response = json!({
        "data": member_list,
        "object": "list",
        "continuationToken": Value::Null,
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/organizations/:org_id/users/invite
pub async fn invite_member(mut req: Request, env: &Env, org_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let inviter = require_membership(&claims.sub, org_id, &d1).await?;
    if inviter.atype > 1 {
        return Err(Error::unauthorized("Only owners and admins can invite members"));
    }

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let emails = body["emails"].as_array().ok_or_else(|| Error::bad_request("emails required"))?;
    let atype = body["type"].as_i64().unwrap_or(MEMBERSHIP_USER as i64) as i32;
    let access_all = body["accessAll"].as_bool().unwrap_or(false);

    for email_val in emails {
        let email = email_val.as_str().unwrap_or("").to_lowercase();
        if email.is_empty() {
            continue;
        }

        // Check if already a member
        let existing: Option<Membership> = db::query_one(
            &d1,
            "SELECT * FROM users_organizations WHERE org_uuid = ?1 AND user_uuid IN (SELECT uuid FROM users WHERE email = ?2)",
            &[db::val(org_id), db::val(&email)],
        ).await?;

        if existing.is_some() {
            continue;
        }

        // Find user or create invitation
        let user = crate::models::User::find_by_email(&email, &d1).await?;
        let user_uuid = match user {
            Some(u) => u.uuid,
            None => {
                // Create invitation record
                db::execute(&d1, "INSERT OR IGNORE INTO invitations (email) VALUES (?1)", &[db::val(&email)]).await?;
                // Store invite with a generated UUID; user is matched by email upon registration
                format!("invite-{}", util::get_uuid())
            }
        };

        let membership = Membership {
            uuid: util::get_uuid(),
            user_uuid,
            org_uuid: org_id.to_string(),
            invited_by_email: Some(claims.email.clone()),
            access_all: if access_all {
                1
            } else {
                0
            },
            akey: String::new(),
            status: MEMBERSHIP_INVITED,
            atype,
            reset_password_key: None,
            external_id: None,
        };
        membership.save(&d1).await?;

        // Send invite email
        let org = Organization::find_by_uuid(org_id, &d1).await?;
        let org_name = org.map(|o| o.name).unwrap_or_else(|| "Organization".to_string());
        let _ = crate::mail::send_org_invite(env, &email, &org_name, &claims.email, "", org_id, &membership.uuid).await;
    }

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/organizations/:org_id/users/:member_id/confirm
pub async fn confirm_member(mut req: Request, env: &Env, org_id: &str, member_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let confirmer = require_membership(&claims.sub, org_id, &d1).await?;
    if confirmer.atype > 1 {
        return Err(Error::unauthorized("Only owners and admins can confirm members"));
    }

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let key = body["key"].as_str().ok_or_else(|| Error::bad_request("key required"))?;

    db::execute(
        &d1,
        "UPDATE users_organizations SET status = ?1, akey = ?2 WHERE uuid = ?3 AND org_uuid = ?4",
        &[db::val_i32(MEMBERSHIP_CONFIRMED), db::val(key), db::val(member_id), db::val(org_id)],
    )
    .await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// DELETE /api/organizations/:org_id/users/:member_id
pub async fn delete_member(req: Request, env: &Env, org_id: &str, member_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let deleter = require_membership(&claims.sub, org_id, &d1).await?;
    if deleter.atype > 1 {
        return Err(Error::unauthorized("Only owners and admins can remove members"));
    }

    db::execute(
        &d1,
        "DELETE FROM users_organizations WHERE uuid = ?1 AND org_uuid = ?2",
        &[db::val(member_id), db::val(org_id)],
    )
    .await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/organizations/:org_id/collections
pub async fn get_collections(req: Request, env: &Env, org_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let _membership = require_membership(&claims.sub, org_id, &d1).await?;

    let collections: Vec<Collection> =
        db::query_all(&d1, "SELECT * FROM collections WHERE org_uuid = ?1", &[db::val(org_id)]).await?;

    let col_list: Vec<Value> = collections.iter().map(|c| c.to_json()).collect();

    let response = json!({
        "data": col_list,
        "object": "list",
        "continuationToken": Value::Null,
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/organizations/:org_id/collections
pub async fn create_collection(mut req: Request, env: &Env, org_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let membership = require_membership(&claims.sub, org_id, &d1).await?;
    if membership.atype > 1 && membership.access_all == 0 {
        return Err(Error::unauthorized("Insufficient permissions"));
    }

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;
    let name = body["name"].as_str().ok_or_else(|| Error::bad_request("name required"))?;

    let col = Collection {
        uuid: util::get_uuid(),
        org_uuid: org_id.to_string(),
        name: name.to_string(),
        external_id: body["externalId"].as_str().map(|s| s.to_string()),
    };

    db::execute(
        &d1,
        "INSERT INTO collections (uuid, org_uuid, name, external_id) VALUES (?1, ?2, ?3, ?4)",
        &[db::val(&col.uuid), db::val(&col.org_uuid), db::val(&col.name), db::val_opt(&col.external_id)],
    )
    .await?;

    Response::from_json(&col.to_json()).map_err(|e| Error::internal(e.to_string()))
}

/// DELETE /api/organizations/:org_id/collections/:col_id
pub async fn delete_collection(req: Request, env: &Env, org_id: &str, col_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let membership = require_membership(&claims.sub, org_id, &d1).await?;
    if membership.atype > 1 {
        return Err(Error::unauthorized("Only owners and admins can delete collections"));
    }

    db::execute(&d1, "DELETE FROM ciphers_collections WHERE collection_uuid = ?1", &[db::val(col_id)]).await?;
    db::execute(&d1, "DELETE FROM users_collections WHERE collection_uuid = ?1", &[db::val(col_id)]).await?;
    db::execute(&d1, "DELETE FROM collections_groups WHERE collections_uuid = ?1", &[db::val(col_id)]).await?;
    db::execute(&d1, "DELETE FROM collections WHERE uuid = ?1 AND org_uuid = ?2", &[db::val(col_id), db::val(org_id)])
        .await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/organizations/:org_id/keys
pub async fn get_org_keys(req: Request, env: &Env, org_id: &str) -> Result<Response> {
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let _membership = require_membership(&claims.sub, org_id, &d1).await?;
    let org =
        Organization::find_by_uuid(org_id, &d1).await?.ok_or_else(|| Error::not_found("Organization not found"))?;

    let response = json!({
        "publicKey": org.public_key,
        "privateKey": org.private_key,
        "object": "organizationKeys",
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// GET /api/plans (static response)
pub fn get_plans() -> Result<Response> {
    let response = json!({
        "data": [],
        "object": "list",
        "continuationToken": Value::Null,
    });
    Response::from_json(&response).map_err(|e| Error::internal(e.to_string()))
}

/// POST /api/organizations/:org_id/users/:member_id/accept
pub async fn accept_invite(mut req: Request, env: &Env, org_id: &str, member_id: &str) -> Result<Response> {
    // Require authentication — the accepting user must be logged in
    let domain = get_domain(env);
    let claims = auth::get_auth_user(&req, &domain, env)?;
    let d1 = env.d1("DB").map_err(|e| Error::internal(e.to_string()))?;

    let body: Value = req.json().await.map_err(|e| Error::bad_request(e.to_string()))?;

    // Update membership status to accepted
    db::execute(
        &d1,
        "UPDATE users_organizations SET status = ?1 WHERE uuid = ?2 AND org_uuid = ?3 AND status = ?4",
        &[db::val_i32(1), db::val(member_id), db::val(org_id), db::val_i32(MEMBERSHIP_INVITED)],
    )
    .await?;

    Response::ok("").map_err(|e| Error::internal(e.to_string()))
}

// ============================================================================
// Helpers
// ============================================================================

async fn require_membership(user_uuid: &str, org_uuid: &str, d1: &worker::D1Database) -> Result<Membership> {
    let membership: Option<Membership> = db::query_one(
        d1,
        "SELECT * FROM users_organizations WHERE user_uuid = ?1 AND org_uuid = ?2",
        &[db::val(user_uuid), db::val(org_uuid)],
    )
    .await?;

    membership.ok_or_else(|| Error::not_found("Not a member of this organization"))
}

fn get_domain(env: &Env) -> String {
    env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_else(|_| "https://vaultwarden.example.com".to_string())
}
