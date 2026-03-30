package com.aikms.kms.hsm;

import com.aikms.common.domain.KeyAlgorithm;

/**
 * Abstraction over physical HSMs, SoftHSM, and the AIKMS HSM simulator.
 * All implementations must be thread-safe.
 */
public interface HsmProvider {

    /** Generate a symmetric key. Returns an opaque handle. */
    String generateSymmetricKey(KeyAlgorithm algorithm, int keySizeBits);

    /** Generate an asymmetric key pair. Returns public key bytes + opaque handle. */
    HsmKeyPairResult generateKeyPair(KeyAlgorithm algorithm);

    /** Encrypt plaintext. Returns IV + ciphertext + GCM tag. */
    EncryptResult encrypt(String hsmHandle, byte[] plaintext, KeyAlgorithm algorithm);

    /** Decrypt ciphertext using the key referenced by hsmHandle. */
    byte[] decrypt(String hsmHandle, byte[] ciphertext, byte[] iv, KeyAlgorithm algorithm);

    /** Sign data using the key referenced by hsmHandle. */
    byte[] sign(String hsmHandle, byte[] data, KeyAlgorithm algorithm);

    /** Verify signature using the key referenced by hsmHandle. */
    boolean verify(String hsmHandle, byte[] data, byte[] signature, KeyAlgorithm algorithm);

    /** Wrap (encrypt) rawKeyBytes using the KEK referenced by kekHandle. */
    EncryptResult wrapKey(String kekHandle, byte[] rawKeyBytes, KeyAlgorithm algorithm);

    /** Securely erase the key material referenced by hsmHandle. Irreversible. */
    void destroyKey(String hsmHandle);

    /** Check connectivity and slot availability. Returns true if healthy. */
    boolean healthCheck();

    record HsmKeyPairResult(String hsmHandle, byte[] publicKeyBytes) {}
    record EncryptResult(byte[] iv, byte[] ciphertext, byte[] tag) {}
}
