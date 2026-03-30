package com.aikms.auth.service;

import com.aikms.auth.domain.Identity;
import com.aikms.auth.domain.Session;
import com.aikms.auth.dto.TokenPair;
import com.aikms.auth.repository.SessionRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final SessionRepository sessionRepository;
    private final JwkKeyService     jwkKeyService;          // manages RSA key pair from Vault / file

    @Value("${aikms.auth.token.issuer}")
    private String issuer;

    @Value("${aikms.auth.token.access-ttl-minutes:15}")
    private int accessTtlMinutes;

    @Value("${aikms.auth.token.refresh-ttl-hours:24}")
    private int refreshTtlHours;

    // ─── Issue ────────────────────────────────────────────────────────────────────

    @Transactional
    public TokenPair issueTokens(Identity identity, String ipAddress, String userAgent) throws JOSEException {
        String accessJti  = UUID.randomUUID().toString();
        String refreshJti = UUID.randomUUID().toString();
        Instant now = Instant.now();

        String roles = identity.getRoles().stream()
                .map(Enum::name)
                .collect(Collectors.joining(" "));

        // ── Access token (short-lived) ──────────────────────────────────────────
        JWTClaimsSet accessClaims = new JWTClaimsSet.Builder()
                .subject(identity.getIdentityId().toString())
                .issuer(issuer)
                .jwtID(accessJti)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(accessTtlMinutes, ChronoUnit.MINUTES)))
                .claim("ns",    identity.getNamespaceId().toString())
                .claim("roles", roles)
                .claim("email", identity.getEmail())
                .build();

        String accessToken = sign(accessClaims);

        // ── Refresh token (long-lived session token stored in DB) ────────────────
        JWTClaimsSet refreshClaims = new JWTClaimsSet.Builder()
                .subject(identity.getIdentityId().toString())
                .issuer(issuer)
                .jwtID(refreshJti)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(refreshTtlHours, ChronoUnit.HOURS)))
                .claim("type", "refresh")
                .build();

        String refreshToken = sign(refreshClaims);

        // ── Persist session ──────────────────────────────────────────────────────
        Session session = Session.builder()
                .identityId(identity.getIdentityId())
                .jti(refreshJti)
                .issuedAt(now)
                .expiresAt(now.plus(refreshTtlHours, ChronoUnit.HOURS))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();
        sessionRepository.save(session);

        return new TokenPair(accessToken, refreshToken, accessTtlMinutes * 60L);
    }

    // ─── Revoke ───────────────────────────────────────────────────────────────────

    @Transactional
    public void revokeRefreshToken(String refreshToken) throws ParseException {
        SignedJWT jwt = SignedJWT.parse(refreshToken);
        String jti = jwt.getJWTClaimsSet().getJWTID();
        sessionRepository.findByJti(jti).ifPresent(s -> {
            s.setRevoked(true);
            s.setRevokedAt(Instant.now());
            sessionRepository.save(s);
        });
    }

    // ─── Validate refresh token for re-issue ──────────────────────────────────────

    public boolean isRefreshTokenValid(String refreshToken) {
        try {
            SignedJWT jwt = SignedJWT.parse(refreshToken);
            jwt.verify(new RSASSAVerifier((RSAPublicKey) jwkKeyService.getPublicKey()));
            String jti = jwt.getJWTClaimsSet().getJWTID();
            return sessionRepository.existsByJtiAndRevokedFalse(jti);
        } catch (Exception ex) {
            log.debug("Refresh token validation failed: {}", ex.getMessage());
            return false;
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    private String sign(JWTClaimsSet claims) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(jwkKeyService.getKeyId())
                .type(JOSEObjectType.JWT)
                .build();
        SignedJWT signed = new SignedJWT(header, claims);
        signed.sign(new RSASSASigner(jwkKeyService.getPrivateKey()));
        return signed.serialize();
    }
}
