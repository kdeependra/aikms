package com.aikms.audit.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
    name = "audit_logs",
    indexes = {
        @Index(name = "idx_audit_resource",   columnList = "resource_type, resource_id"),
        @Index(name = "idx_audit_namespace",  columnList = "namespace_id"),
        @Index(name = "idx_audit_actor",      columnList = "actor_id"),
        @Index(name = "idx_audit_occurred",   columnList = "occurred_at")
    }
)
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "audit_id", updatable = false, nullable = false)
    private UUID auditId;

    @Column(name = "event_id", nullable = false, unique = true, length = 64)
    private String eventId;

    @Column(name = "action",        nullable = false, length = 100)
    private String action;

    @Column(name = "resource_type", nullable = false, length = 50)
    private String resourceType;

    @Column(name = "resource_id",   length = 128)
    private String resourceId;

    @Column(name = "namespace_id")
    private String namespaceId;

    @Column(name = "actor_id",      length = 128)
    private String actorId;

    @Column(name = "ip_address",    length = 45)
    private String ipAddress;

    @Column(name = "success",       nullable = false)
    private boolean success;

    @Column(name = "failure_reason", length = 500)
    private String failureReason;

    @Column(name = "correlation_id", length = 64)
    private String correlationId;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Column(name = "service_name",   length = 100)
    private String serviceName;
}
