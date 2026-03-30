package com.aikms.kms.service;

import com.aikms.common.domain.KeyPurpose;
import com.aikms.common.event.AuditEvent;
import com.aikms.common.event.KeyUsageEvent;
import com.aikms.common.exception.KeyNotFoundException;
import com.aikms.common.exception.PolicyDeniedException;
import com.aikms.common.util.KafkaTopics;
import com.aikms.kms.domain.Key;
import com.aikms.kms.domain.KeyVersion;
import com.aikms.kms.dto.*;
import com.aikms.kms.hsm.HsmProvider;
import com.aikms.kms.repository.KeyRepository;
import com.aikms.kms.repository.KeyVersionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class CryptoService {

    private final KeyRepository        keyRepository;
    private final KeyVersionRepository keyVersionRepository;
    private final HsmProvider          hsmProvider;
    private final KafkaTemplate<String, Object> kafkaTemplate;

    // ─── Encrypt ─────────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public CryptoResponse encrypt(UUID keyId, UUID namespaceId, CryptoRequest request, UUID actorId) {
        Key key = resolveActiveKey(keyId, namespaceId, KeyPurpose.ENCRYPT);
        KeyVersion version = resolveVersion(key, request.keyVersionNumber());

        byte[] plaintext = java.util.Base64.getDecoder().decode(request.dataBase64());
        HsmProvider.EncryptResult result = hsmProvider.encrypt(version.getHsmKeyHandle(), plaintext, key.getAlgorithm());

        String ciphertextB64 = java.util.Base64.getEncoder().encodeToString(result.ciphertext());
        String ivB64         = java.util.Base64.getEncoder().encodeToString(result.iv());
        String tagB64        = result.tag() != null
                ? java.util.Base64.getEncoder().encodeToString(result.tag()) : null;

        publishUsageEvent("ENCRYPT", key, version, actorId, true, null);
        return new CryptoResponse(ciphertextB64, ivB64, tagB64, version.getVersionNumber(), null);
    }

    // ─── Decrypt ─────────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public CryptoResponse decrypt(UUID keyId, UUID namespaceId, CryptoRequest request, UUID actorId) {
        Key key = resolveKey(keyId, namespaceId, KeyPurpose.DECRYPT);
        KeyVersion version = resolveVersion(key, request.keyVersionNumber());

        byte[] ciphertext = java.util.Base64.getDecoder().decode(request.dataBase64());
        byte[] iv         = request.ivBase64() != null
                ? java.util.Base64.getDecoder().decode(request.ivBase64()) : null;

        byte[] plaintext = hsmProvider.decrypt(version.getHsmKeyHandle(), ciphertext, iv, key.getAlgorithm());

        publishUsageEvent("DECRYPT", key, version, actorId, true, null);
        return new CryptoResponse(
                java.util.Base64.getEncoder().encodeToString(plaintext), null, null, version.getVersionNumber(), null);
    }

    // ─── Sign ─────────────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public CryptoResponse sign(UUID keyId, UUID namespaceId, CryptoRequest request, UUID actorId) {
        Key key = resolveActiveKey(keyId, namespaceId, KeyPurpose.SIGN);
        KeyVersion version = resolveVersion(key, request.keyVersionNumber());

        byte[] data = java.util.Base64.getDecoder().decode(request.dataBase64());
        byte[] signature = hsmProvider.sign(version.getHsmKeyHandle(), data, key.getAlgorithm());

        publishUsageEvent("SIGN", key, version, actorId, true, null);
        return new CryptoResponse(
                java.util.Base64.getEncoder().encodeToString(signature), null, null, version.getVersionNumber(), null);
    }

    // ─── Verify ──────────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public VerifyResponse verify(UUID keyId, UUID namespaceId, VerifyRequest request, UUID actorId) {
        Key key = resolveKey(keyId, namespaceId, KeyPurpose.VERIFY);
        KeyVersion version = resolveVersion(key, request.keyVersionNumber());

        byte[] data      = java.util.Base64.getDecoder().decode(request.dataBase64());
        byte[] signature = java.util.Base64.getDecoder().decode(request.signatureBase64());
        boolean valid    = hsmProvider.verify(version.getHsmKeyHandle(), data, signature, key.getAlgorithm());

        publishUsageEvent("VERIFY", key, version, actorId, valid, valid ? null : "Signature mismatch");
        return new VerifyResponse(valid, version.getVersionNumber());
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    private Key resolveActiveKey(UUID keyId, UUID namespaceId, KeyPurpose required) {
        Key key = resolveKey(keyId, namespaceId, required);
        if (!key.getState().isUsableForEncryption() && required == KeyPurpose.ENCRYPT) {
            throw new PolicyDeniedException("Key " + keyId + " is not in ACTIVE state");
        }
        return key;
    }

    private Key resolveKey(UUID keyId, UUID namespaceId, KeyPurpose required) {
        Key key = keyRepository.findByKeyIdAndNamespaceId(keyId, namespaceId)
                .orElseThrow(() -> new KeyNotFoundException(keyId.toString()));
        if (!key.getPurposes().contains(required)) {
            throw new PolicyDeniedException("Key " + keyId + " does not have purpose " + required);
        }
        return key;
    }

    private KeyVersion resolveVersion(Key key, Integer explicitVersion) {
        if (explicitVersion != null) {
            return keyVersionRepository
                    .findByKey_KeyIdAndVersionNumber(key.getKeyId(), explicitVersion)
                    .orElseThrow(() -> new KeyNotFoundException(
                            "Version " + explicitVersion + " of key " + key.getKeyId()));
        }
        return keyVersionRepository
                .findLatestByKeyId(key.getKeyId())
                .orElseThrow(() -> new KeyNotFoundException("No version found for key " + key.getKeyId()));
    }

    private void publishUsageEvent(String operation, Key key, KeyVersion version,
                                   UUID actorId, boolean success, String reason) {
        var event = KeyUsageEvent.of(
                key.getKeyId().toString(),
                String.valueOf(version.getVersionNumber()),
                key.getNamespaceId().toString(),
                actorId != null ? actorId.toString() : "SYSTEM",
                operation,
                null, null, success, reason, 0L);
        kafkaTemplate.send(KafkaTopics.KEY_USAGE_EVENTS, key.getKeyId().toString(), event);

        var audit = success
                ? AuditEvent.success(operation, "KEY", key.getKeyId().toString(),
                        key.getNamespaceId().toString(),
                        actorId != null ? actorId.toString() : "SYSTEM", null, null, null)
                : AuditEvent.failure(operation, "KEY", key.getKeyId().toString(),
                        key.getNamespaceId().toString(),
                        actorId != null ? actorId.toString() : "SYSTEM", null, reason, null, null);
        kafkaTemplate.send(KafkaTopics.AUDIT_EVENTS, key.getKeyId().toString(), audit);
    }
}
