package com.aikms.kms.service;

import com.aikms.common.domain.KeyState;
import com.aikms.common.event.AuditEvent;
import com.aikms.common.event.KeyLifecycleEvent;
import com.aikms.common.exception.KeyNotFoundException;
import com.aikms.common.util.KafkaTopics;
import com.aikms.kms.domain.Key;
import com.aikms.kms.domain.KeyVersion;
import com.aikms.kms.domain.RotationPolicy;
import com.aikms.kms.repository.KeyRepository;
import com.aikms.kms.repository.KeyVersionRepository;
import com.aikms.kms.repository.RotationPolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeyRotationService {

    private final KeyRepository              keyRepository;
    private final KeyVersionRepository       keyVersionRepository;
    private final RotationPolicyRepository   rotationPolicyRepository;
    private final EnvelopeEncryptionService  envelopeEncryptionService;
    private final KafkaTemplate<String, Object> kafkaTemplate;

    // ─── Manual rotation ─────────────────────────────────────────────────────────

    @Transactional
    public KeyVersion rotateKey(UUID keyId, UUID namespaceId, UUID actorId) {
        Key key = keyRepository.findByKeyIdAndNamespaceId(keyId, namespaceId)
                .orElseThrow(() -> new KeyNotFoundException(keyId.toString()));

        if (key.getState() != KeyState.ACTIVE) {
            throw new IllegalStateException("Key must be ACTIVE to rotate. Current state: " + key.getState());
        }

        // Deprecate old versions (the previous current version)
        keyVersionRepository.findLatestByKeyId(keyId).ifPresent(old -> {
            old.setExpiresAt(Instant.now().plus(90, ChronoUnit.DAYS));
            keyVersionRepository.save(old);
        });

        // Generate new key material version
        KeyVersion newVersion = envelopeEncryptionService.rotateVersion(key);
        key.setCurrentVersion(newVersion.getVersionNumber());
        key.setUpdatedAt(Instant.now());
        keyRepository.save(key);

        publishLifecycleEvent("KEY_ROTATED", key, key.getCurrentVersion() - 1, newVersion.getVersionNumber(), actorId);
        publishAuditEvent("KEY_ROTATE", key, actorId);

        log.info("Key rotated: id={} new_version={}", keyId, newVersion.getVersionNumber());
        return newVersion;
    }

    // ─── Scheduled auto-rotation ──────────────────────────────────────────────────

    @Scheduled(cron = "0 0 2 * * *")   // 02:00 UTC daily
    @Transactional
    public void scheduledRotationSweep() {
        log.info("Starting scheduled rotation sweep");
        List<Key> candidates = keyRepository.findAllExpiringSoon(Instant.now().plus(30, ChronoUnit.DAYS));
        for (Key key : candidates) {
            if (key.getRotationPolicyId() == null) continue;
            rotationPolicyRepository.findById(key.getRotationPolicyId()).ifPresent(policy -> {
                if (shouldAutoRotate(key, policy)) {
                    try {
                        rotateKey(key.getKeyId(), key.getNamespaceId(), null);
                    } catch (Exception ex) {
                        log.error("Auto-rotation failed for key {}: {}", key.getKeyId(), ex.getMessage());
                    }
                }
            });
        }
        log.info("Rotation sweep complete");
    }

    // ─── Scheduled destruction sweep ──────────────────────────────────────────────

    @Scheduled(cron = "0 30 2 * * *")  // 02:30 UTC daily
    @Transactional
    public void scheduledDestructionSweep() {
        log.info("Starting destruction sweep");
        List<Key> condemned = keyRepository.findReadyForDestruction(Instant.now());
        condemned.forEach(key -> {
            try {
                key.setState(KeyState.DESTROYED);
                key.setUpdatedAt(Instant.now());
                keyRepository.save(key);
                publishLifecycleEvent("KEY_DESTROYED", key,
                        KeyState.SCHEDULED_DESTROY.name(), KeyState.DESTROYED.name(), null);
            } catch (Exception ex) {
                log.error("Auto-destruction failed for key {}: {}", key.getKeyId(), ex.getMessage());
            }
        });
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    private boolean shouldAutoRotate(Key key, RotationPolicy policy) {
        if (policy.getRotationIntervalDays() == null) return false;
        Instant lastRotatedAt = keyVersionRepository.findLatestByKeyId(key.getKeyId())
                .map(KeyVersion::getCreatedAt)
                .orElse(key.getCreatedAt());
        return lastRotatedAt.plus(policy.getRotationIntervalDays(), ChronoUnit.DAYS).isBefore(Instant.now());
    }

    private void publishLifecycleEvent(String type, Key key, Object oldVersion, Object newVersion, UUID actorId) {
        var event = KeyLifecycleEvent.of(type,
                key.getKeyId().toString(),
                key.getNamespaceId().toString(),
                key.getName(),
                oldVersion != null ? oldVersion.toString() : null,
                newVersion != null ? newVersion.toString() : null,
                actorId != null ? actorId.toString() : "SCHEDULER");
        kafkaTemplate.send(KafkaTopics.KEY_LIFECYCLE_EVENTS, key.getKeyId().toString(), event);
    }

    private void publishLifecycleEvent(String type, Key key, String from, String to, UUID actorId) {
        publishLifecycleEvent(type, key, (Object) from, (Object) to, actorId);
    }

    private void publishAuditEvent(String action, Key key, UUID actorId) {
        var event = AuditEvent.success(action, "KEY", key.getKeyId().toString(),
                key.getNamespaceId().toString(),
                actorId != null ? actorId.toString() : "SCHEDULER",
                null, null, null);
        kafkaTemplate.send(KafkaTopics.AUDIT_EVENTS, key.getKeyId().toString(), event);
    }
}
