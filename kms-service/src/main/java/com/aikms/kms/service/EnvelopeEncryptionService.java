package com.aikms.kms.service;

import com.aikms.kms.domain.Key;
import com.aikms.kms.domain.KeyVersion;
import com.aikms.kms.hsm.HsmProvider;
import com.aikms.kms.repository.KeyVersionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

/**
 * Envelope-encryption helper.
 *
 * Key material never leaves the HSM / software HSM vault.  For software-backed
 * keys we generate a random Data-Encryption Key (DEK) in JVM memory, use the
 * HSM to wrap (encrypt) that DEK with the master Key-Encryption Key (KEK), and
 * store only the wrapped DEK bytes in the database.  The raw DEK is zeroed
 * immediately after wrapping.
 *
 * For HSM-backed keys the HSM generates the key natively; only the opaque
 * handle is stored.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EnvelopeEncryptionService {

    private static final int VERSION_ONE       = 1;
    private static final int DEK_SIZE_BYTES    = 32;   // 256-bit DEK

    private final HsmProvider          hsmProvider;
    private final KeyVersionRepository keyVersionRepository;

    // ─── Generate + wrap ─────────────────────────────────────────────────────────

    @Transactional
    public KeyVersion generateAndWrapKey(Key key) {
        if (key.isHsmBacked()) {
            return generateHsmKey(key);
        }
        return generateSoftwareKey(key);
    }

    // ─── Re-wrap on rotation ──────────────────────────────────────────────────────

    /**
     * Called by KeyRotationService: re-wraps the current DEK under a fresh KEK
     * derived from the same master.  Returns the new KeyVersion (not yet active).
     */
    @Transactional
    public KeyVersion rotateVersion(Key key) {
        return generateAndWrapKey(key);
    }

    // ─── Internal ─────────────────────────────────────────────────────────────────

    private KeyVersion generateHsmKey(Key key) {
        String handle;
        if (key.getAlgorithm().isSymmetric()) {
            handle = hsmProvider.generateSymmetricKey(key.getAlgorithm(), key.getKeySizeBits());
        } else {
            handle = hsmProvider.generateKeyPair(key.getAlgorithm()).hsmHandle();
        }

        KeyVersion version = KeyVersion.builder()
                .key(key)
                .versionNumber(nextVersionNumber(key))
                .hsmKeyHandle(handle)
                .createdAt(Instant.now())
                .build();
        return keyVersionRepository.save(version);
    }

    private KeyVersion generateSoftwareKey(Key key) {
        // 1.  Generate a random DEK in JVM memory
        byte[] rawDek = new byte[DEK_SIZE_BYTES];
        new SecureRandom().nextBytes(rawDek);

        try {
            // 2.  Wrap (encrypt) the DEK using the HSM's master KEK
            HsmProvider.EncryptResult wrapped =
                    hsmProvider.encrypt(null, rawDek, key.getAlgorithm());

            // 3.  Persist only the wrapped DEK; never the raw bytes
            KeyVersion version = KeyVersion.builder()
                    .key(key)
                    .versionNumber(nextVersionNumber(key))
                    .encryptedKeyDek(wrapped.ciphertext())
                    .dekIv(wrapped.iv())
                    .dekTag(wrapped.tag())
                    .createdAt(Instant.now())
                    .build();
            return keyVersionRepository.save(version);

        } finally {
            // 4.  Zero the raw DEK
            java.util.Arrays.fill(rawDek, (byte) 0);
        }
    }

    private int nextVersionNumber(Key key) {
        return keyVersionRepository
                .findLatestByKeyId(key.getKeyId())
                .map(v -> v.getVersionNumber() + 1)
                .orElse(VERSION_ONE);
    }
}
