package com.aikms.notification.kafka;

import com.aikms.common.event.KeyLifecycleEvent;
import com.aikms.common.util.KafkaTopics;
import com.aikms.notification.service.NotificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class NotificationConsumer {

    private final NotificationService notificationService;

    @KafkaListener(topics = KafkaTopics.NOTIFICATION_DISPATCH, groupId = "notification-service")
    public void onNotification(NotificationMessage message) {
        notificationService.dispatch(message);
    }

    @KafkaListener(topics = KafkaTopics.KEY_LIFECYCLE_EVENTS, groupId = "notification-lifecycle")
    public void onLifecycleEvent(KeyLifecycleEvent event) {
        // Forward critical lifecycle events as notifications
        if (isCritical(event.eventType())) {
            notificationService.dispatchLifecycleAlert(event);
        }
    }

    private boolean isCritical(String eventType) {
        return switch (eventType) {
            case "KEY_DESTROYED", "KEY_ROTATED", "KEY_COMPROMISED" -> true;
            default -> false;
        };
    }

    public record NotificationMessage(
            String channel,
            String recipient,
            String subject,
            String body,
            String templateId,
            java.util.Map<String, String> variables
    ) {}
}
