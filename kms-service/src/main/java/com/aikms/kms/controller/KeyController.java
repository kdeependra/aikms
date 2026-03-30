package com.aikms.kms.controller;

import com.aikms.common.domain.KeyState;
import com.aikms.kms.dto.*;
import com.aikms.kms.service.CryptoService;
import com.aikms.kms.service.KeyLifecycleService;
import com.aikms.kms.service.KeyRotationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST controller for key lifecycle management and crypto operations.
 *
 * All endpoints are scoped under /api/v1/namespaces/{namespaceId}/keys.
 * The namespace-id is extracted from the path; the caller's identity is taken
 * from the JWT subject claim.
 */
@RestController
@RequestMapping("/api/v1/namespaces/{namespaceId}/keys")
@RequiredArgsConstructor
public class KeyController {

    private final KeyLifecycleService  keyLifecycleService;
    private final CryptoService        cryptoService;
    private final KeyRotationService   keyRotationService;

    // ─── CRUD ─────────────────────────────────────────────────────────────────────

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public KeyResponse createKey(
            @PathVariable UUID namespaceId,
            @Valid @RequestBody CreateKeyRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        return keyLifecycleService.createKey(request, actorId(jwt), namespaceId);
    }

    @GetMapping("/{keyId}")
    public KeyResponse getKey(
            @PathVariable UUID namespaceId,
            @PathVariable UUID keyId,
            @AuthenticationPrincipal Jwt jwt) {
        return keyLifecycleService.getKey(keyId, namespaceId);
    }

    @GetMapping
    public Page<KeyResponse> listKeys(
            @PathVariable UUID namespaceId,
            @RequestParam(required = false) KeyState state,
            @PageableDefault(size = 20) Pageable pageable,
            @AuthenticationPrincipal Jwt jwt) {
        return keyLifecycleService.listKeys(namespaceId, state, pageable);
    }

    // ─── State transitions ────────────────────────────────────────────────────────

    @PostMapping("/{keyId}/suspend")
    public KeyResponse suspendKey(
            @PathVariable UUID namespaceId,
            @PathVariable UUID keyId,
            @AuthenticationPrincipal Jwt jwt) {
        return keyLifecycleService.suspendKey(keyId, namespaceId, actorId(jwt));
    }

    @PostMapping("/{keyId}/resume")
    public KeyResponse resumeKey(
            @PathVariable UUID namespaceId,
            @PathVariable UUID keyId,
            @AuthenticationPrincipal Jwt jwt) {
        return keyLifecycleService.resumeKey(keyId, namespaceId, actorId(jwt));
    }

    @PostMapping("/{keyId}/schedule-destroy")
    public KeyResponse scheduleDestruction(
            @PathVariable UUID namespaceId,
            @PathVariable UUID keyId,
            @AuthenticationPrincipal Jwt jwt) {
        return keyLifecycleService.scheduleDestruction(keyId, namespaceId, actorId(jwt));
    }

    @PostMapping("/{keyId}/rotate")
    public void rotateKey(
            @PathVariable UUID namespaceId,
            @PathVariable UUID keyId,
            @AuthenticationPrincipal Jwt jwt) {
        keyRotationService.rotateKey(keyId, namespaceId, actorId(jwt));
    }

    // ─── Crypto ───────────────────────────────────────────────────────────────────

    @PostMapping("/{keyId}/encrypt")
    public CryptoResponse encrypt(
            @PathVariable UUID namespaceId,
            @PathVariable UUID keyId,
            @Valid @RequestBody CryptoRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        return cryptoService.encrypt(keyId, namespaceId, request, actorId(jwt));
    }

    @PostMapping("/{keyId}/decrypt")
    public CryptoResponse decrypt(
            @PathVariable UUID namespaceId,
            @PathVariable UUID keyId,
            @Valid @RequestBody CryptoRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        return cryptoService.decrypt(keyId, namespaceId, request, actorId(jwt));
    }

    @PostMapping("/{keyId}/sign")
    public CryptoResponse sign(
            @PathVariable UUID namespaceId,
            @PathVariable UUID keyId,
            @Valid @RequestBody CryptoRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        return cryptoService.sign(keyId, namespaceId, request, actorId(jwt));
    }

    @PostMapping("/{keyId}/verify")
    public VerifyResponse verify(
            @PathVariable UUID namespaceId,
            @PathVariable UUID keyId,
            @Valid @RequestBody VerifyRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        return cryptoService.verify(keyId, namespaceId, request, actorId(jwt));
    }

    // ─── Helper ───────────────────────────────────────────────────────────────────

    private UUID actorId(Jwt jwt) {
        return UUID.fromString(jwt.getSubject());
    }
}
