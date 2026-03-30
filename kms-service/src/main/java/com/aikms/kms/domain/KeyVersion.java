package com.aikms.kms.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "key_versions",
       indexes = {
           @Index(name = "idx_key_versions_key", columnList = "key_id")
       },
       uniqueConstraints = {
           @UniqueConstraint(columnNames = {"key_id", "version_number"})
       })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class KeyVersion {

    @Id
    @Column(name = "version_id", updatable = false, nullable = false)
    @Builder.Default
    private UUID versionId = UUID.randomUUID();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_id", nullable = false)
    private Key key;

    @Column(name = "version_number", nullable = false)
    private Integer versionNumber;

    /**
     * The key's DEK (Data Encryption Key) encrypted with the namespace KEK.
     * Raw key material is NEVER stored here; only cipher text.
     */
    @Column(name = "encrypted_key_dek", nullable = false)
    private byte[] encryptedKeyDek;

    /**
     * Nonce / IV used when wrapping the DEK.
     */
    @Column(name = "dek_iv", nullable = false)
    private byte[] dekIv;

    /**
     * GCM authentication tag for the wrapped DEK.
     */
    @Column(name = "dek_tag", nullable = false)
    private byte[] dekTag;

    /**
     * For HSM-backed keys: the opaque handle/reference in the HSM, not the key itself.
     */
    @Column(name = "hsm_key_handle", length = 512)
    private String hsmKeyHandle;

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "destroyed_at")
    private Instant destroyedAt;
}
