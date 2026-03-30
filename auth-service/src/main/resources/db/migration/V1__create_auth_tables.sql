-- V1: Auth service schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE identities (
    identity_id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id        UUID        NOT NULL,
    username            VARCHAR(255) NOT NULL UNIQUE,
    password_hash       VARCHAR(500) NOT NULL,
    email               VARCHAR(320),
    enabled             BOOLEAN     NOT NULL DEFAULT TRUE,
    locked_until        TIMESTAMPTZ,
    failed_login_count  INTEGER     NOT NULL DEFAULT 0,
    mfa_enabled         BOOLEAN     NOT NULL DEFAULT FALSE,
    mfa_secret          VARCHAR(64),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_identity_username  ON identities (username);
CREATE INDEX idx_identity_namespace ON identities (namespace_id);

CREATE TABLE identity_roles (
    identity_id UUID        NOT NULL REFERENCES identities(identity_id) ON DELETE CASCADE,
    role        VARCHAR(50) NOT NULL,
    PRIMARY KEY (identity_id, role)
);

CREATE TABLE sessions (
    session_id   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id  UUID        NOT NULL REFERENCES identities(identity_id) ON DELETE CASCADE,
    jti          VARCHAR(64) NOT NULL UNIQUE,
    issued_at    TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked      BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at   TIMESTAMPTZ,
    ip_address   VARCHAR(45),
    user_agent   VARCHAR(500)
);

CREATE INDEX idx_session_identity ON sessions (identity_id);
CREATE INDEX idx_session_jti      ON sessions (jti);
CREATE INDEX idx_session_expires  ON sessions (expires_at);
