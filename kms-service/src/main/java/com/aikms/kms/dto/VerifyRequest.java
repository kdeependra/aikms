package com.aikms.kms.dto;

import jakarta.validation.constraints.NotBlank;

public record VerifyRequest(
        @NotBlank String dataBase64,
        @NotBlank String signatureBase64,
        Integer   keyVersionNumber
) {}
