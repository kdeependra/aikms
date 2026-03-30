package com.aikms.auth.dto;

public record TokenPair(String accessToken, String refreshToken, long expiresIn) {}
