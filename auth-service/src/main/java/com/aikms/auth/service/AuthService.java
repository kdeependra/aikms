package com.aikms.auth.service;

import com.aikms.auth.domain.Identity;
import com.aikms.auth.dto.*;
import com.aikms.auth.repository.IdentityRepository;
import com.aikms.auth.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final int    MAX_FAILED = 5;
    private static final long   LOCK_MINUTES = 15;

    private final IdentityRepository identityRepository;
    private final SessionRepository  sessionRepository;
    private final TokenService       tokenService;
    private final PasswordEncoder    passwordEncoder;

    // ─── Login ────────────────────────────────────────────────────────────────────

    @Transactional
    public TokenResponse login(LoginRequest request, String ipAddress, String userAgent) throws Exception {
        Identity identity = identityRepository.findByUsername(request.username())
                .orElseThrow(() -> new org.springframework.security.authentication.BadCredentialsException("Invalid credentials"));

        if (!identity.isEnabled()) {
            throw new org.springframework.security.authentication.DisabledException("Account disabled");
        }
        if (identity.getLockedUntil() != null && Instant.now().isBefore(identity.getLockedUntil())) {
            throw new org.springframework.security.authentication.LockedException("Account locked until " + identity.getLockedUntil());
        }

        if (!passwordEncoder.matches(request.password(), identity.getPasswordHash())) {
            identity.setFailedLoginCount(identity.getFailedLoginCount() + 1);
            if (identity.getFailedLoginCount() >= MAX_FAILED) {
                identity.setLockedUntil(Instant.now().plusSeconds(LOCK_MINUTES * 60));
                log.warn("Account {} locked after {} failed attempts", identity.getUsername(), MAX_FAILED);
            }
            identityRepository.save(identity);
            throw new org.springframework.security.authentication.BadCredentialsException("Invalid credentials");
        }

        // Reset failed count on success
        identity.setFailedLoginCount(0);
        identity.setLockedUntil(null);
        identityRepository.save(identity);

        TokenPair tokens = tokenService.issueTokens(identity, ipAddress, userAgent);
        log.info("Login success: user={}", identity.getUsername());
        return new TokenResponse(tokens.accessToken(), tokens.refreshToken(), tokens.expiresIn(), "Bearer");
    }

    // ─── Refresh ──────────────────────────────────────────────────────────────────

    @Transactional
    public TokenResponse refresh(RefreshRequest request, String ipAddress, String userAgent) throws Exception {
        if (!tokenService.isRefreshTokenValid(request.refreshToken())) {
            throw new org.springframework.security.authentication.CredentialsExpiredException("Refresh token is invalid or revoked");
        }
        // Rotate: revoke old, issue new
        tokenService.revokeRefreshToken(request.refreshToken());
        com.nimbusds.jwt.SignedJWT jwt = com.nimbusds.jwt.SignedJWT.parse(request.refreshToken());
        String subject = jwt.getJWTClaimsSet().getSubject();
        Identity identity = identityRepository.findById(java.util.UUID.fromString(subject))
                .orElseThrow(() -> new org.springframework.security.core.userdetails.UsernameNotFoundException("Identity not found"));
        TokenPair tokens = tokenService.issueTokens(identity, ipAddress, userAgent);
        return new TokenResponse(tokens.accessToken(), tokens.refreshToken(), tokens.expiresIn(), "Bearer");
    }

    // ─── Logout ───────────────────────────────────────────────────────────────────

    @Transactional
    public void logout(String refreshToken) throws Exception {
        tokenService.revokeRefreshToken(refreshToken);
    }
}
