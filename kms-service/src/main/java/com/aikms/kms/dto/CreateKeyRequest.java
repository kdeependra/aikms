package com.aikms.kms.dto;

import com.aikms.common.domain.KeyAlgorithm;
import com.aikms.common.domain.KeyPurpose;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public record CreateKeyRequest(
        @NotBlank String name,
        @NotNull  KeyAlgorithm algorithm,
        Integer   keySizeBits,
        @NotEmpty Set<KeyPurpose> purposes,
        boolean   hsmBacked,
        String    description,
        UUID      rotationPolicyId,
        Instant   expiresAt,
        Map<String, String> tags
) {}
