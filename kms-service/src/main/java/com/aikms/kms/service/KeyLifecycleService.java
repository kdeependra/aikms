package com.aikms.kms.service;

import com.aikms.common.domain.KeyState;
import com.aikms.common.event.AuditEvent;
import com.aikms.common.event.KeyLifecycleEvent;
import com.aikms.common.exception.KeyNotFoundException;
import com.aikms.common.exception.KeyStateConflictException;
import com.aikms.common.util.KafkaTopics;
import com.aikms.kms.domain.Key;
import com.aikms.kms.domain.KeyVersion;
import com.aikms.kms.dto.*;
import com.aikms.kms.hsm.HsmProvider;
import com.aikms.kms.repository.KeyRepository;
import com.aikms.kms.repository.KeyVersionRepository;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeyLifecycleService {

    private final KeyRepository         keyRepository;
    private final KeyVersionRepository  keyVersionRepository;
    private final HsmProvider           hsmProvider;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final EnvelopeEncryptionService envelopeEncryptionService;

    // ─── Create ─────────────────────────────────────────────────────────────────

    @Transactional
    public KeyResponse createKey(CreateKeyRequest request, UUID actorId, UUID namespaceId) {
        validateNoNameDuplicate(request.name(), namespaceId);

        Key key = Key.builder()
                .name(request.name())
                .namespaceId(namespaceId)
                .algorithm(request.algorithm())
                .keySizeBits(request.keySizeBits() != null ? request.keySizeBits() : request.algorithm().getKeySizeBits())
                .purposes(request.purposes())
                .hsmBacked(request.hsmBacked())
                .description(request.description())
                .ownerId(actorId)
                .createdBy(actorId)
                .expiresAt(request.expiresAt())
                .tags(request.tags() != null ? request.tags() : java.util.Map.of())
                .state(KeyState.PENDING)
                .build();

        key = keyRepository.save(key);

        // Generate key material via HSM / software provider
        KeyVersion version = envelopeEncryptionService.generateAndWrapKey(key);
        key.setCurrentVersion(version.getVersionNumber());
        key.setState(KeyState.ACTIVE);
        key = keyRepository.save(key);

        publishLifecycleEvent("KEY_CREATED", key, null, KeyState.ACTIVE.name(), actorId);
        publishAuditEvent("KEY_CREATE", key, "SUCCESS", null, actorId);

        log.info("Key created: id={} name={} ns={}", key.getKeyId(), key.getName(), namespaceId);
        return KeyResponse.from(key);
    }

    // ─── Read ────────────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public KeyResponse getKey(UUID keyId, UUID namespaceId) {
        return KeyResponse.from(findKeyInNamespace(keyId, namespaceId));
    }

    @Transactional(readOnly = true)
    public Page<KeyResponse> listKeys(UUID namespaceId, KeyState stateFilter, Pageable pageable) {
        Page<Key> page = stateFilter != null
                ? keyRepository.findByNamespaceIdAndState(namespaceId, stateFilter, pageable)
                : keyRepository.findByNamespaceId(namespaceId, pageable);
        return page.map(KeyResponse::from);
    }

    // ─── Suspend / Resume ────────────────────────────────────────────────────────

    @Transactional
    public KeyResponse suspendKey(UUID keyId, UUID namespaceId, UUID actorId) {
        Key key = findKeyInNamespace(keyId, namespaceId);
        transitionState(key, KeyState.SUSPENDED, actorId);
        return KeyResponse.from(keyRepository.save(key));
    }

    @Transactional
    public KeyResponse resumeKey(UUID keyId, UUID namespaceId, UUID actorId) {
        Key key = findKeyInNamespace(keyId, namespaceId);
        transitionState(key, KeyState.ACTIVE, actorId);
        return KeyResponse.from(keyRepository.save(key));
    }

    // ─── Schedule Destruction ────────────────────────────────────────────────────

    @Transactional
    public KeyResponse scheduleDestruction(UUID keyId, UUID namespaceId, UUID actorId) {
        Key key = findKeyInNamespace(keyId, namespaceId);
        transitionState(key, KeyState.SCHEDULED_DESTROY, actorId);
        return KeyResponse.from(keyRepository.save(key));
    }

    // ─── Destroy (called by scheduler after cooling-off) ────────────────────────

    @Transactional
    public void destroyKey(UUID keyId) {
        Key key = keyRepository.findById(keyId)
                .orElseThrow(() -> new KeyNotFoundException(keyId.toString()));

        if (key.getState() != KeyState.SCHEDULED_DESTROY) {
            throw new KeyStateConflictException(keyId.toString(), key.getState().name(), "DESTROY");
        }

        // Erase key material from HSM for each version
        key.getVersions().forEach(v -> {
            if (v.getHsmKeyHandle() != null) {
                try {
                    hsmProvider.destroyKey(v.getHsmKeyHandle());
                } catch (Exception ex) {
                    log.error("HSM key erasure failed for version {}: {}", v.getVersionId(), ex.getMessage());
                }
            }
            v.setDestroyedAt(java.time.Instant.now());
        });

        key.setState(KeyState.DESTROYED);
        key.setUpdatedAt(java.time.Instant.now());
        keyRepository.save(key);

        publishLifecycleEvent("KEY_DESTROYED", key, KeyState.SCHEDULED_DESTROY.name(), KeyState.DESTROYED.name(), null);
        publishAuditEvent("KEY_DESTROY", key, "SUCCESS", null, null);
        log.info("Key destroyed: id={}", keyId);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    private void transitionState(Key key, KeyState target, UUID actorId) {
        if (!key.getState().canTransitionTo(target)) {
            throw new KeyStateConflictException(
                    key.getKeyId().toString(), key.getState().name(), "transition to " + target);
        }
        KeyState previous = key.getState();
        key.setState(target);
        key.setUpdatedAt(java.time.Instant.now());
        publishLifecycleEvent("KEY_STATE_CHANGED", key, previous.name(), target.name(), actorId);
        publishAuditEvent("KEY_STATE_CHANGE", key, "SUCCESS", null, actorId);
    }

    private Key findKeyInNamespace(UUID keyId, UUID namespaceId) {
        return keyRepository.findByKeyIdAndNamespaceId(keyId, namespaceId)
                .orElseThrow(() -> new KeyNotFoundException(keyId.toString()));
    }

    private void validateNoNameDuplicate(String name, UUID namespaceId) {
        if (keyRepository.existsByNameAndNamespaceId(name, namespaceId)) {
            throw new IllegalArgumentException("A key named '" + name + "' already exists in namespace " + namespaceId);
        }
    }

    private void publishLifecycleEvent(String type, Key key, String from, String to, UUID actorId) {
        var event = KeyLifecycleEvent.of(type,
                key.getKeyId().toString(),
                key.getNamespaceId().toString(),
                key.getName(), from, to,
                actorId != null ? actorId.toString() : "SYSTEM");
        kafkaTemplate.send(KafkaTopics.KEY_LIFECYCLE_EVENTS, key.getKeyId().toString(), event);
    }

    private void publishAuditEvent(String action, Key key, String outcome, String reason, UUID actorId) {
        var event = outcome.equals("SUCCESS")
                ? AuditEvent.success(action, "KEY", key.getKeyId().toString(),
                        key.getNamespaceId().toString(),
                        actorId != null ? actorId.toString() : "SYSTEM",
                        null, null, null)
                : AuditEvent.failure(action, "KEY", key.getKeyId().toString(),
                        key.getNamespaceId().toString(),
                        actorId != null ? actorId.toString() : "SYSTEM",
                        null, reason, null, null);
        kafkaTemplate.send(KafkaTopics.AUDIT_EVENTS, key.getKeyId().toString(), event);
    }
}
