package com.aikms.common.event;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a key usage event published to Kafka for anomaly detection.
 */
public record KeyUsageEvent(
    String eventId,
    String keyId,
    String keyVersionId,
    String namespaceId,
    String callerId,
    String operationType,   // ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP, UNWRAP
    String sourceIp,
    String userAgent,
    boolean success,
    String failureReason,
    long latencyMs,
    Instant occurredAt
) {
    public static KeyUsageEvent of(String keyId, String keyVersionId, String namespaceId,
                                    String callerId, String operationType,
                                    String sourceIp, String userAgent,
                                    boolean success, String failureReason, long latencyMs) {
        return new KeyUsageEvent(
            UUID.randomUUID().toString(),
            keyId, keyVersionId, namespaceId, callerId,
            operationType, sourceIp, userAgent,
            success, failureReason, latencyMs,
            Instant.now()
        );
    }
}
