package com.aikms.policy.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
    name = "policies",
    indexes = {
        @Index(name = "idx_policy_namespace", columnList = "namespace_id"),
        @Index(name = "idx_policy_name",      columnList = "name")
    }
)
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class Policy {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "policy_id", updatable = false, nullable = false)
    private UUID policyId;

    @Column(name = "namespace_id", nullable = false)
    private UUID namespaceId;

    @Column(nullable = false, length = 255)
    private String name;

    /** OPA Rego policy source text */
    @Column(name = "rego_source", columnDefinition = "TEXT", nullable = false)
    private String regoSource;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "created_by")
    private UUID createdBy;

    @PrePersist
    void onCreate() { createdAt = updatedAt = Instant.now(); }

    @PreUpdate
    void onUpdate() { updatedAt = Instant.now(); }
}
