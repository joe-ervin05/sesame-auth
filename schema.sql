CREATE TABLE sessions (
    id TEXT NOT NULL PRIMARY KEY,
    secret_hash BLOB NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    auth_level INTEGER NOT NULL DEFAULT 2,
    last_verified_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    created_at INTEGER NOT NULL
);

CREATE INDEX sessions_user_id_idx ON sessions(user_id);

CREATE TABLE users (
    id TEXT NOT NULL PRIMARY KEY,
    created_at INTEGER NOT NULL,

    -- Shared identity fields
    email TEXT UNIQUE,
    email_verified INTEGER NOT NULL DEFAULT 0,

    -- Password storage (only needed if you support email & password login)
    password_hash TEXT
);

CREATE TABLE email_verification_codes (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    email TEXT NOT NULL,
    code_hash BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX email_verification_codes_user_id_idx ON email_verification_codes(user_id);

CREATE TABLE password_reset_tokens (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX password_reset_tokens_user_id_idx ON password_reset_tokens(user_id);

CREATE TABLE oauth_accounts (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX oauth_accounts_user_id_idx ON oauth_accounts(user_id);

CREATE TABLE token_buckets (
    storage_key TEXT NOT NULL,
    bucket_key TEXT NOT NULL,
    count INTEGER NOT NULL,
    refilled_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY(storage_key, bucket_key)
);

CREATE INDEX token_buckets_updated_at_ms_idx ON token_buckets(updated_at_ms);

CREATE TABLE user_totp_credentials (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
    secret_encrypted TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE user_recovery_codes (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    code_hash BLOB NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE INDEX user_recovery_codes_user_id_idx ON user_recovery_codes(user_id);

CREATE TABLE user_totp_pending_setups (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash BLOB NOT NULL UNIQUE,
    secret_encrypted TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX user_totp_pending_setups_user_id_idx ON user_totp_pending_setups(user_id);

CREATE TABLE user_passkeys (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    credential_id BLOB NOT NULL UNIQUE,
    credential_json BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX user_passkeys_user_id_idx ON user_passkeys(user_id);

CREATE TABLE webauthn_flows (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT,
    flow_type TEXT NOT NULL,
    session_data_json BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX webauthn_flows_expires_at_idx ON webauthn_flows(expires_at);

CREATE TABLE email_magic_links (
    id TEXT NOT NULL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX email_magic_links_email_idx ON email_magic_links(email);
CREATE INDEX email_magic_links_expires_at_idx ON email_magic_links(expires_at);

CREATE TABLE email_otp_codes (
    id TEXT NOT NULL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    code_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX email_otp_codes_email_idx ON email_otp_codes(email);
CREATE INDEX email_otp_codes_expires_at_idx ON email_otp_codes(expires_at);
