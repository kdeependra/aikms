package com.aikms.kms.domain;

import com.aikms.common.domain.KeyAlgorithm;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "rotation_policies")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RotationPolicy {

    @Id
    @Column(name = "rotation_policy_id", updatable = false, nullable = false)
    @Builder.Default
    private UUID rotationPolicyId = UUID.randomUUID();

    @Column(name = "namespace_id")
    private UUID namespaceId;

    @Enumerated(EnumType.STRING)
    @Column(name = "applies_to_algorithm", length = 32)
    private KeyAlgorithm appliesToAlgorithm;

    @Column(name = "rotation_interval_days")
    private Integer rotationIntervalDays;

    @Column(name = "max_usage_count")
    private Long maxUsageCount;

    @Column(name = "anomaly_score_threshold", precision = 5, scale = 2)
    private java.math.BigDecimal anomalyScoreThreshold;

    @Column(name = "notify_lead_days", nullable = false)
    @Builder.Default
    private Integer notifyLeadDays = 14;

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();
}
