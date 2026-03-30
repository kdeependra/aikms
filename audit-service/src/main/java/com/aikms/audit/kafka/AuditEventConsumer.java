package com.aikms.audit.kafka;

import com.aikms.audit.domain.AuditLog;
import com.aikms.audit.repository.AuditLogRepository;
import com.aikms.common.event.AuditEvent;
import com.aikms.common.util.KafkaTopics;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuditEventConsumer {

    private final AuditLogRepository auditLogRepository;

    @KafkaListener(topics = KafkaTopics.AUDIT_EVENTS, groupId = "audit-service")
    public void onAuditEvent(AuditEvent event) {
        AuditLog auditLog = AuditLog.builder()
                .eventId(event.auditId())
                .action(event.action())
                .resourceType(event.resourceType())
                .resourceId(event.resourceId())
                .namespaceId(event.namespaceId())
                .actorId(event.actorId())
                .ipAddress(event.actorIp())
                .success("SUCCESS".equalsIgnoreCase(event.outcome()))
                .failureReason(event.failureReason())
                .correlationId(event.correlationId())
                .occurredAt(event.occurredAt())
                .build();
        auditLogRepository.save(auditLog);
        log.debug("Audit persisted: eventId={}", event.auditId());
    }
}
