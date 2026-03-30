-- V1: Audit log schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE audit_logs (
    audit_id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        VARCHAR(64) NOT NULL UNIQUE,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(50) NOT NULL,
    resource_id     VARCHAR(128),
    namespace_id    VARCHAR(128),
    actor_id        VARCHAR(128),
    ip_address      VARCHAR(45),
    success         BOOLEAN     NOT NULL,
    failure_reason  VARCHAR(500),
    correlation_id  VARCHAR(64),
    occurred_at     TIMESTAMPTZ NOT NULL,
    service_name    VARCHAR(100)
);

CREATE INDEX idx_audit_resource   ON audit_logs (resource_type, resource_id);
CREATE INDEX idx_audit_namespace  ON audit_logs (namespace_id);
CREATE INDEX idx_audit_actor      ON audit_logs (actor_id);
CREATE INDEX idx_audit_occurred   ON audit_logs (occurred_at);
