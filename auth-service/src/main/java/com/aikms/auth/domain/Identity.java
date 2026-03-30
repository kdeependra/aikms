package com.aikms.auth.domain;

import com.aikms.common.domain.IdentityRole;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(
    name = "identities",
    indexes = {
        @Index(name = "idx_identity_username", columnList = "username"),
        @Index(name = "idx_identity_namespace", columnList = "namespace_id")
    }
)
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class Identity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "identity_id", updatable = false, nullable = false)
    private UUID identityId;

    @Column(name = "namespace_id", nullable = false)
    private UUID namespaceId;

    @Column(nullable = false, unique = true, length = 255)
    private String username;

    /** bcrypt/argon2 hash — never plain text */
    @Column(name = "password_hash", nullable = false, length = 500)
    private String passwordHash;

    @Column(name = "email", length = 320)
    private String email;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "identity_roles", joinColumns = @JoinColumn(name = "identity_id"))
    @Column(name = "role")
    @Enumerated(EnumType.STRING)
    private Set<IdentityRole> roles;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "failed_login_count")
    private int failedLoginCount;

    @Column(name = "mfa_enabled", nullable = false)
    private boolean mfaEnabled = false;

    @Column(name = "mfa_secret", length = 64)
    private String mfaSecret;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
