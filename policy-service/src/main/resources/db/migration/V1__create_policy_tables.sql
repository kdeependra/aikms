CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE policies (
    policy_id    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID        NOT NULL,
    name         VARCHAR(255) NOT NULL,
    rego_source  TEXT        NOT NULL,
    enabled      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   UUID,
    CONSTRAINT uq_policy_ns_name UNIQUE (namespace_id, name)
);

CREATE INDEX idx_policy_namespace ON policies (namespace_id);
