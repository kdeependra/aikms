-- V1: Initial KMS schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── rotation_policies ───────────────────────────────────────────────────────
CREATE TABLE rotation_policies (
    rotation_policy_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id                UUID,
    applies_to_algorithm        VARCHAR(32),
    rotation_interval_days      INTEGER,
    max_usage_count             BIGINT,
    anomaly_score_threshold     DECIMAL(5,4),
    notify_lead_days            INTEGER     NOT NULL DEFAULT 14,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── keys ────────────────────────────────────────────────────────────────────
CREATE TABLE keys (
    key_id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(255) NOT NULL,
    namespace_id        UUID        NOT NULL,
    algorithm           VARCHAR(50) NOT NULL,
    key_size_bits       INTEGER     NOT NULL,
    state               VARCHAR(30) NOT NULL DEFAULT 'PENDING',
    current_version     INTEGER     NOT NULL DEFAULT 1,
    risk_score          DECIMAL(6,4) NOT NULL DEFAULT 0,
    hsm_backed          BOOLEAN     NOT NULL DEFAULT FALSE,
    description         TEXT,
    owner_id            UUID,
    rotation_policy_id  UUID        REFERENCES rotation_policies(rotation_policy_id),
    expires_at          TIMESTAMPTZ,
    tags                JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID,

    CONSTRAINT uq_key_name_ns UNIQUE (name, namespace_id)
);

CREATE INDEX idx_keys_namespace   ON keys (namespace_id);
CREATE INDEX idx_keys_state       ON keys (state);
CREATE INDEX idx_keys_expires     ON keys (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_keys_risk        ON keys (risk_score DESC);

-- ─── key_purposes (element collection) ───────────────────────────────────────
CREATE TABLE key_purposes (
    key_id   UUID        NOT NULL REFERENCES keys(key_id) ON DELETE CASCADE,
    purpose  VARCHAR(30) NOT NULL,
    PRIMARY KEY (key_id, purpose)
);

-- ─── key_versions ─────────────────────────────────────────────────────────────
CREATE TABLE key_versions (
    version_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id              UUID        NOT NULL REFERENCES keys(key_id) ON DELETE CASCADE,
    version_number      INTEGER     NOT NULL,
    encrypted_key_dek   BYTEA,
    dek_iv              BYTEA,
    dek_tag             BYTEA,
    hsm_key_handle      VARCHAR(512),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ,
    destroyed_at        TIMESTAMPTZ,

    CONSTRAINT uq_key_version UNIQUE (key_id, version_number),
    CONSTRAINT chk_key_material CHECK (
        (hsm_key_handle IS NOT NULL) OR (encrypted_key_dek IS NOT NULL)
    )
);

CREATE INDEX idx_kv_key_id ON key_versions (key_id);
