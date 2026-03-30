package com.aikms.kms.dto;

import com.aikms.common.domain.KeyAlgorithm;
import com.aikms.common.domain.KeyPurpose;
import com.aikms.common.domain.KeyState;
import com.aikms.kms.domain.Key;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public record KeyResponse(
        UUID       keyId,
        String     name,
        UUID       namespaceId,
        KeyAlgorithm algorithm,
        int        keySizeBits,
        Set<KeyPurpose> purposes,
        KeyState   state,
        int        currentVersion,
        boolean    hsmBacked,
        String     description,
        UUID       ownerId,
        Instant    createdAt,
        Instant    updatedAt,
        Instant    expiresAt,
        Map<String, String> tags
) {
    public static KeyResponse from(Key key) {
        return new KeyResponse(
                key.getKeyId(),
                key.getName(),
                key.getNamespaceId(),
                key.getAlgorithm(),
                key.getKeySizeBits(),
                key.getPurposes(),
                key.getState(),
                key.getCurrentVersion(),
                key.isHsmBacked(),
                key.getDescription(),
                key.getOwnerId(),
                key.getCreatedAt(),
                key.getUpdatedAt(),
                key.getExpiresAt(),
                key.getTags()
        );
    }
}
