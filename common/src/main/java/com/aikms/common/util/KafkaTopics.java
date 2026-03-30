package com.aikms.common.util;

/**
 * Central constants for Kafka topic names shared across all services.
 */
public final class KafkaTopics {

    private KafkaTopics() {}

    public static final String KEY_LIFECYCLE_EVENTS  = "key-lifecycle-events";
    public static final String KEY_USAGE_EVENTS      = "key-usage-events";
    public static final String ANOMALY_EVENTS        = "anomaly-events";
    public static final String AUDIT_EVENTS          = "audit-events";
    public static final String ROTATION_COMMANDS     = "rotation-commands";
    public static final String NOTIFICATION_DISPATCH = "notification-dispatch";
}
