package com.aikms.kms.domain;

import com.aikms.common.domain.KeyAlgorithm;
import com.aikms.common.domain.KeyPurpose;
import com.aikms.common.domain.KeyState;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.*;

@Entity
@Table(name = "keys",
       indexes = {
           @Index(name = "idx_keys_namespace", columnList = "namespace_id"),
           @Index(name = "idx_keys_state",     columnList = "state"),
           @Index(name = "idx_keys_expires",   columnList = "expires_at")
       })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Key {

    @Id
    @Column(name = "key_id", updatable = false, nullable = false)
    @Builder.Default
    private UUID keyId = UUID.randomUUID();

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "namespace_id", nullable = false)
    private UUID namespaceId;

    @Enumerated(EnumType.STRING)
    @Column(name = "algorithm", nullable = false, length = 32)
    private KeyAlgorithm algorithm;

    @Column(name = "key_size_bits", nullable = false)
    private Integer keySizeBits;

    @ElementCollection(targetClass = KeyPurpose.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "key_purposes", joinColumns = @JoinColumn(name = "key_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "purpose")
    @Builder.Default
    private Set<KeyPurpose> purposes = EnumSet.noneOf(KeyPurpose.class);

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false, length = 32)
    @Builder.Default
    private KeyState state = KeyState.PENDING;

    @Column(name = "current_version", nullable = false)
    @Builder.Default
    private Integer currentVersion = 1;

    @Column(name = "risk_score", precision = 5, scale = 2)
    @Builder.Default
    private BigDecimal riskScore = BigDecimal.ZERO;

    @Column(name = "hsm_backed", nullable = false)
    @Builder.Default
    private boolean hsmBacked = false;

    @Column(name = "description")
    private String description;

    @Column(name = "owner_id")
    private UUID ownerId;

    @Column(name = "rotation_policy_id")
    private UUID rotationPolicyId;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    @Builder.Default
    private Instant updatedAt = Instant.now();

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "tags", columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, String> tags = new HashMap<>();

    @OneToMany(mappedBy = "key", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("versionNumber DESC")
    @Builder.Default
    private List<KeyVersion> versions = new ArrayList<>();

    @PreUpdate
    void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
