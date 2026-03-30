package com.aikms.auth.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
    name = "sessions",
    indexes = {
        @Index(name = "idx_session_identity", columnList = "identity_id"),
        @Index(name = "idx_session_jti",      columnList = "jti", unique = true)
    }
)
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class Session {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "session_id", updatable = false, nullable = false)
    private UUID sessionId;

    @Column(name = "identity_id", nullable = false)
    private UUID identityId;

    @Column(name = "jti", nullable = false, unique = true, length = 64)
    private String jti;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked", nullable = false)
    private boolean revoked = false;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;
}
