package com.aikms.common.event;

import java.time.Instant;
import java.util.UUID;

/**
 * Base event published to Kafka for all key lifecycle state changes.
 */
public record KeyLifecycleEvent(
    String eventId,
    String eventType,
    String keyId,
    String namespaceId,
    String keyName,
    String fromState,
    String toState,
    String actorId,
    String correlationId,
    Instant occurredAt
) {
    public static KeyLifecycleEvent of(String eventType, String keyId, String namespaceId,
                                       String keyName, String fromState, String toState,
                                       String actorId) {
        return new KeyLifecycleEvent(
            UUID.randomUUID().toString(),
            eventType,
            keyId,
            namespaceId,
            keyName,
            fromState,
            toState,
            actorId,
            UUID.randomUUID().toString(),
            Instant.now()
        );
    }
}
