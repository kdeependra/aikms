package com.aikms.kms.dto;

import jakarta.validation.constraints.NotBlank;

public record CryptoRequest(
        @NotBlank String dataBase64,
        String    ivBase64,
        String    tagBase64,
        Integer   keyVersionNumber,
        String    aadBase64
) {}
