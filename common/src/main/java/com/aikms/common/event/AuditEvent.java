package com.aikms.common.event;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable audit event written by every AIKMS service.
 */
public record AuditEvent(
    String auditId,
    String action,
    String resourceType,
    String resourceId,
    String namespaceId,
    String actorId,
    String actorIp,
    String outcome,         // SUCCESS | FAILURE
    String failureReason,
    String correlationId,
    String requestId,
    Instant occurredAt
) {
    public static AuditEvent success(String action, String resourceType, String resourceId,
                                      String namespaceId, String actorId, String actorIp,
                                      String correlationId, String requestId) {
        return new AuditEvent(
            UUID.randomUUID().toString(), action, resourceType, resourceId,
            namespaceId, actorId, actorIp, "SUCCESS", null,
            correlationId, requestId, Instant.now()
        );
    }

    public static AuditEvent failure(String action, String resourceType, String resourceId,
                                      String namespaceId, String actorId, String actorIp,
                                      String reason, String correlationId, String requestId) {
        return new AuditEvent(
            UUID.randomUUID().toString(), action, resourceType, resourceId,
            namespaceId, actorId, actorIp, "FAILURE", reason,
            correlationId, requestId, Instant.now()
        );
    }
}
