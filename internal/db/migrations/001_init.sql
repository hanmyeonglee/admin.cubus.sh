CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS admin_kv (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash BYTEA PRIMARY KEY,
    email      TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    csrf_token TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions (expires_at);

CREATE TABLE IF NOT EXISTS oidc_transactions (
    tx_hash       BYTEA PRIMARY KEY,
    state         TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    next_path     TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_oidc_tx_expires ON oidc_transactions (expires_at);

CREATE TABLE IF NOT EXISTS audit_logs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_email    TEXT NOT NULL,
    auth_method    TEXT NOT NULL,
    action         TEXT NOT NULL,
    target_service TEXT NOT NULL,
    target_id      TEXT NOT NULL DEFAULT '',
    details        JSONB NOT NULL DEFAULT '{}'::jsonb,
    client_ip      TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_service ON audit_logs (target_service, created_at DESC);
