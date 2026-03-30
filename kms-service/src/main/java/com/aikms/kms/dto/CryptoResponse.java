package com.aikms.kms.dto;

public record CryptoResponse(
        String  dataBase64,
        String  ivBase64,
        String  tagBase64,
        int     keyVersionNumber,
        String  algorithm
) {}
