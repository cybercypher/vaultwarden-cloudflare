-- Vaultwarden D1 Schema
-- Compatible with Bitwarden API, adapted from original vaultwarden SQLite schema

CREATE TABLE IF NOT EXISTS users (
    uuid TEXT NOT NULL PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    verified_at TEXT,
    last_verifying_at TEXT,
    login_verify_count INTEGER NOT NULL DEFAULT 0,
    email TEXT NOT NULL UNIQUE,
    email_new TEXT,
    email_new_token TEXT,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    password_iterations INTEGER NOT NULL DEFAULT 600000,
    password_hint TEXT,
    akey TEXT NOT NULL,
    private_key TEXT,
    public_key TEXT,
    totp_secret TEXT,
    totp_recover TEXT,
    security_stamp TEXT NOT NULL,
    stamp_exception TEXT,
    equivalent_domains TEXT NOT NULL DEFAULT '[]',
    excluded_globals TEXT NOT NULL DEFAULT '[]',
    client_kdf_type INTEGER NOT NULL DEFAULT 0,
    client_kdf_iter INTEGER NOT NULL DEFAULT 600000,
    client_kdf_memory INTEGER,
    client_kdf_parallelism INTEGER,
    api_key TEXT,
    avatar_color TEXT,
    external_id TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    uuid TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    user_uuid TEXT NOT NULL REFERENCES users(uuid),
    name TEXT NOT NULL,
    atype INTEGER NOT NULL,
    push_uuid TEXT,
    push_token TEXT,
    refresh_token TEXT NOT NULL,
    twofactor_remember TEXT,
    PRIMARY KEY (uuid, user_uuid)
);

CREATE TABLE IF NOT EXISTS ciphers (
    uuid TEXT NOT NULL PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    user_uuid TEXT REFERENCES users(uuid),
    organization_uuid TEXT REFERENCES organizations(uuid),
    akey TEXT,
    atype INTEGER NOT NULL,
    name TEXT NOT NULL,
    notes TEXT,
    fields TEXT,
    data TEXT NOT NULL,
    password_history TEXT,
    deleted_at TEXT,
    reprompt INTEGER
);

CREATE TABLE IF NOT EXISTS folders (
    uuid TEXT NOT NULL PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    user_uuid TEXT NOT NULL REFERENCES users(uuid),
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS folders_ciphers (
    cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),
    folder_uuid TEXT NOT NULL REFERENCES folders(uuid),
    PRIMARY KEY (cipher_uuid, folder_uuid)
);

CREATE TABLE IF NOT EXISTS favorites (
    user_uuid TEXT NOT NULL REFERENCES users(uuid),
    cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),
    PRIMARY KEY (user_uuid, cipher_uuid)
);

CREATE TABLE IF NOT EXISTS attachments (
    id TEXT NOT NULL PRIMARY KEY,
    cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    akey TEXT
);

CREATE TABLE IF NOT EXISTS organizations (
    uuid TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    billing_email TEXT NOT NULL,
    private_key TEXT,
    public_key TEXT
);

CREATE TABLE IF NOT EXISTS users_organizations (
    uuid TEXT NOT NULL PRIMARY KEY,
    user_uuid TEXT NOT NULL REFERENCES users(uuid),
    org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
    invited_by_email TEXT,
    access_all INTEGER NOT NULL DEFAULT 0,
    akey TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL,
    atype INTEGER NOT NULL,
    reset_password_key TEXT,
    external_id TEXT
);

CREATE TABLE IF NOT EXISTS collections (
    uuid TEXT NOT NULL PRIMARY KEY,
    org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
    name TEXT NOT NULL,
    external_id TEXT
);

CREATE TABLE IF NOT EXISTS users_collections (
    user_uuid TEXT NOT NULL REFERENCES users(uuid),
    collection_uuid TEXT NOT NULL REFERENCES collections(uuid),
    read_only INTEGER NOT NULL DEFAULT 0,
    hide_passwords INTEGER NOT NULL DEFAULT 0,
    manage INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE TABLE IF NOT EXISTS ciphers_collections (
    cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),
    collection_uuid TEXT NOT NULL REFERENCES collections(uuid),
    PRIMARY KEY (cipher_uuid, collection_uuid)
);

CREATE TABLE IF NOT EXISTS org_policies (
    uuid TEXT NOT NULL PRIMARY KEY,
    org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
    atype INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    data TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS sends (
    uuid TEXT NOT NULL PRIMARY KEY,
    user_uuid TEXT REFERENCES users(uuid),
    organization_uuid TEXT REFERENCES organizations(uuid),
    name TEXT NOT NULL,
    notes TEXT,
    atype INTEGER NOT NULL,
    data TEXT NOT NULL,
    akey TEXT NOT NULL,
    password_hash TEXT,
    password_salt TEXT,
    password_iter INTEGER,
    max_access_count INTEGER,
    access_count INTEGER NOT NULL DEFAULT 0,
    creation_date TEXT NOT NULL,
    revision_date TEXT NOT NULL,
    expiration_date TEXT,
    deletion_date TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    hide_email INTEGER
);

CREATE TABLE IF NOT EXISTS twofactor (
    uuid TEXT NOT NULL PRIMARY KEY,
    user_uuid TEXT NOT NULL REFERENCES users(uuid),
    atype INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    data TEXT NOT NULL,
    last_used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS twofactor_incomplete (
    user_uuid TEXT NOT NULL,
    device_uuid TEXT NOT NULL,
    device_name TEXT NOT NULL,
    device_type INTEGER NOT NULL,
    login_time TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    PRIMARY KEY (user_uuid, device_uuid)
);

CREATE TABLE IF NOT EXISTS invitations (
    email TEXT NOT NULL PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS emergency_access (
    uuid TEXT NOT NULL PRIMARY KEY,
    grantor_uuid TEXT NOT NULL REFERENCES users(uuid),
    grantee_uuid TEXT,
    email TEXT,
    key_encrypted TEXT,
    atype INTEGER NOT NULL,
    status INTEGER NOT NULL,
    wait_time_days INTEGER NOT NULL,
    recovery_initiated_at TEXT,
    last_notification_at TEXT,
    updated_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    uuid TEXT NOT NULL PRIMARY KEY,
    organizations_uuid TEXT NOT NULL REFERENCES organizations(uuid),
    name TEXT NOT NULL,
    access_all INTEGER NOT NULL DEFAULT 0,
    external_id TEXT,
    creation_date TEXT NOT NULL,
    revision_date TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups_users (
    groups_uuid TEXT NOT NULL REFERENCES groups(uuid),
    users_organizations_uuid TEXT NOT NULL REFERENCES users_organizations(uuid),
    PRIMARY KEY (groups_uuid, users_organizations_uuid)
);

CREATE TABLE IF NOT EXISTS collections_groups (
    collections_uuid TEXT NOT NULL REFERENCES collections(uuid),
    groups_uuid TEXT NOT NULL REFERENCES groups(uuid),
    read_only INTEGER NOT NULL DEFAULT 0,
    hide_passwords INTEGER NOT NULL DEFAULT 0,
    manage INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (collections_uuid, groups_uuid)
);

CREATE TABLE IF NOT EXISTS event (
    uuid TEXT NOT NULL PRIMARY KEY,
    event_type INTEGER NOT NULL,
    user_uuid TEXT,
    org_uuid TEXT,
    cipher_uuid TEXT,
    collection_uuid TEXT,
    group_uuid TEXT,
    org_user_uuid TEXT,
    act_user_uuid TEXT,
    device_type INTEGER,
    ip_address TEXT,
    event_date TEXT NOT NULL,
    policy_uuid TEXT,
    provider_uuid TEXT,
    provider_user_uuid TEXT,
    provider_org_uuid TEXT
);

CREATE TABLE IF NOT EXISTS auth_requests (
    uuid TEXT NOT NULL PRIMARY KEY,
    user_uuid TEXT NOT NULL REFERENCES users(uuid),
    organization_uuid TEXT,
    request_device_identifier TEXT NOT NULL,
    device_type INTEGER NOT NULL,
    request_ip TEXT NOT NULL,
    response_device_id TEXT,
    access_code TEXT NOT NULL,
    public_key TEXT NOT NULL,
    enc_key TEXT,
    master_password_hash TEXT,
    approved INTEGER,
    creation_date TEXT NOT NULL,
    response_date TEXT,
    authentication_date TEXT
);

CREATE TABLE IF NOT EXISTS organization_api_key (
    uuid TEXT NOT NULL,
    org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
    atype INTEGER NOT NULL,
    api_key TEXT NOT NULL,
    revision_date TEXT NOT NULL,
    PRIMARY KEY (uuid, org_uuid)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_devices_user_uuid ON devices(user_uuid);
CREATE INDEX IF NOT EXISTS idx_devices_refresh_token ON devices(refresh_token);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_uuid ON ciphers(user_uuid);
CREATE INDEX IF NOT EXISTS idx_ciphers_org_uuid ON ciphers(organization_uuid);
CREATE INDEX IF NOT EXISTS idx_folders_user_uuid ON folders(user_uuid);
CREATE INDEX IF NOT EXISTS idx_favorites_user_uuid ON favorites(user_uuid);
CREATE INDEX IF NOT EXISTS idx_attachments_cipher_uuid ON attachments(cipher_uuid);
CREATE INDEX IF NOT EXISTS idx_users_organizations_user_uuid ON users_organizations(user_uuid);
CREATE INDEX IF NOT EXISTS idx_users_organizations_org_uuid ON users_organizations(org_uuid);
CREATE INDEX IF NOT EXISTS idx_collections_org_uuid ON collections(org_uuid);
CREATE INDEX IF NOT EXISTS idx_sends_user_uuid ON sends(user_uuid);
CREATE INDEX IF NOT EXISTS idx_twofactor_user_uuid ON twofactor(user_uuid);
CREATE INDEX IF NOT EXISTS idx_event_user_uuid ON event(user_uuid);
CREATE INDEX IF NOT EXISTS idx_event_org_uuid ON event(org_uuid);
