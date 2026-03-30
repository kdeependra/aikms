package com.aikms.notification.service;

import com.aikms.common.event.KeyLifecycleEvent;
import com.aikms.notification.kafka.NotificationConsumer.NotificationMessage;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    private final JavaMailSender mailSender;

    public void dispatch(NotificationMessage msg) {
        if ("EMAIL".equalsIgnoreCase(msg.channel())) {
            sendEmail(msg.recipient(), msg.subject(), msg.body());
        } else {
            log.warn("Unsupported notification channel: {}", msg.channel());
        }
    }

    public void dispatchLifecycleAlert(KeyLifecycleEvent event) {
        String subject = "[AIKMS] Key lifecycle alert: " + event.eventType();
        String body = String.format("""
                Key lifecycle event: %s
                Key ID:       %s
                Key Name:     %s
                Namespace:    %s
                State change: %s → %s
                Actor:        %s
                Timestamp:    %s
                """,
                event.eventType(), event.keyId(), event.keyName(),
                event.namespaceId(), event.fromState(), event.toState(),
                event.actorId(), event.occurredAt());
        log.info("Lifecycle alert dispatched for event: {}", event.eventType());
        // In production: resolve owner email from identity service and send
    }

    private void sendEmail(String to, String subject, String body) {
        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, false, "UTF-8");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(body, false);
            mailSender.send(msg);
            log.info("Email sent to {}: {}", to, subject);
        } catch (Exception ex) {
            log.error("Failed to send email to {}: {}", to, ex.getMessage());
        }
    }
}
