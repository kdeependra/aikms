package com.aikms.kms.hsm;

import com.aikms.common.domain.KeyAlgorithm;
import com.aikms.common.exception.HsmUnavailableException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Software-backed HSM provider using BouncyCastle.
 * Used in development and test environments.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "aikms.hsm.provider", havingValue = "SOFTWARE", matchIfMissing = true)
public class SoftwareHsmProvider implements HsmProvider {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static final String MASTER_KEK_HANDLE = "MASTER_KEK";

    private static final int GCM_IV_LEN  = 12;
    private static final int GCM_TAG_LEN = 128;

    private final Map<String, Object> keyStore = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

    public SoftwareHsmProvider() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES", "BC");
            kg.init(256, secureRandom);
            keyStore.put(MASTER_KEK_HANDLE, kg.generateKey());
            log.info("Software HSM initialized with master KEK");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize master KEK", e);
        }
    }

    @Override
    @Retry(name = "hsm")
    @CircuitBreaker(name = "hsm")
    public String generateSymmetricKey(KeyAlgorithm algorithm, int keySizeBits) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(algorithm.getJcaName(), "BC");
            kg.init(keySizeBits, secureRandom);
            SecretKey key = kg.generateKey();
            String handle = algorithm.name() + ":" + System.nanoTime();
            keyStore.put(handle, key);
            log.debug("Generated symmetric key: handle={}", handle);
            return handle;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new HsmUnavailableException("Key generation failed: " + e.getMessage(), e);
        }
    }

    @Override
    @Retry(name = "hsm")
    @CircuitBreaker(name = "hsm")
    public HsmKeyPairResult generateKeyPair(KeyAlgorithm algorithm) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm.getJcaName(), "BC");
            if ("EC".equals(algorithm.getJcaName())) {
                String curve = switch (algorithm.getKeySizeBits()) {
                    case 256 -> "P-256";
                    case 384 -> "P-384";
                    case 521 -> "P-521";
                    default  -> throw new IllegalArgumentException("Unsupported EC size: " + algorithm.getKeySizeBits());
                };
                kpg.initialize(new ECGenParameterSpec(curve), secureRandom);
            } else {
                kpg.initialize(algorithm.getKeySizeBits(), secureRandom);
            }
            KeyPair kp = kpg.generateKeyPair();
            String handle = algorithm.name() + ":" + System.nanoTime();
            keyStore.put(handle, kp);
            log.debug("Generated key pair: handle={}", handle);
            return new HsmKeyPairResult(handle, kp.getPublic().getEncoded());
        } catch (Exception e) {
            throw new HsmUnavailableException("Key pair generation failed: " + e.getMessage(), e);
        }
    }

    @Override
    @Retry(name = "hsm")
    @CircuitBreaker(name = "hsm")
    public EncryptResult encrypt(String hsmHandle, byte[] plaintext, KeyAlgorithm algorithm) {
        String resolvedHandle = hsmHandle != null ? hsmHandle : MASTER_KEK_HANDLE;
        SecretKey key = getSecretKey(resolvedHandle);
        try {
            byte[] iv = new byte[GCM_IV_LEN];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LEN, iv));
            byte[] ciphertextWithTag = cipher.doFinal(plaintext);
            int ctLen = ciphertextWithTag.length - 16;
            byte[] ct  = new byte[ctLen];
            byte[] tag = new byte[16];
            System.arraycopy(ciphertextWithTag, 0,     ct,  0, ctLen);
            System.arraycopy(ciphertextWithTag, ctLen, tag, 0, 16);
            return new EncryptResult(iv, ct, tag);
        } catch (Exception e) {
            throw new HsmUnavailableException("Encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    @Retry(name = "hsm")
    @CircuitBreaker(name = "hsm")
    public byte[] decrypt(String hsmHandle, byte[] ciphertext, byte[] iv, KeyAlgorithm algorithm) {
        String resolvedHandle = hsmHandle != null ? hsmHandle : MASTER_KEK_HANDLE;
        SecretKey key = getSecretKey(resolvedHandle);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LEN, iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new HsmUnavailableException("Decryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    @Retry(name = "hsm")
    @CircuitBreaker(name = "hsm")
    public byte[] sign(String hsmHandle, byte[] data, KeyAlgorithm algorithm) {
        if (!(keyStore.get(hsmHandle) instanceof KeyPair kp))
            throw new HsmUnavailableException("Key is not an asymmetric key pair: " + hsmHandle);
        try {
            Signature sig = Signature.getInstance(signingAlgorithmFor(algorithm), "BC");
            sig.initSign(kp.getPrivate(), secureRandom);
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            throw new HsmUnavailableException("Sign failed: " + e.getMessage(), e);
        }
    }

    @Override
    @Retry(name = "hsm")
    @CircuitBreaker(name = "hsm")
    public boolean verify(String hsmHandle, byte[] data, byte[] signature, KeyAlgorithm algorithm) {
        if (!(keyStore.get(hsmHandle) instanceof KeyPair kp))
            throw new HsmUnavailableException("Key is not an asymmetric key pair: " + hsmHandle);
        try {
            Signature sig = Signature.getInstance(signingAlgorithmFor(algorithm), "BC");
            sig.initVerify(kp.getPublic());
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            throw new HsmUnavailableException("Verify failed: " + e.getMessage(), e);
        }
    }

    @Override
    public EncryptResult wrapKey(String kekHandle, byte[] rawKeyBytes, KeyAlgorithm algorithm) {
        return encrypt(kekHandle, rawKeyBytes, algorithm);
    }

    @Override
    public void destroyKey(String hsmHandle) {
        if (keyStore.remove(hsmHandle) == null) {
            log.warn("destroyKey called for unknown handle: {}", hsmHandle);
        } else {
            log.info("Key destroyed: handle={}", hsmHandle);
        }
    }

    @Override
    public boolean healthCheck() {
        return true;
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    private SecretKey getSecretKey(String handle) {
        Object obj = keyStore.get(handle);
        if (obj instanceof SecretKey sk) return sk;
        throw new HsmUnavailableException("Secret key not found for handle: " + handle);
    }

    private static String signingAlgorithmFor(KeyAlgorithm algorithm) {
        return switch (algorithm) {
            case RSA_2048, RSA_3072, RSA_4096 -> "SHA256WithRSA";
            case EC_P256 -> "SHA256WithECDSA";
            case EC_P384 -> "SHA384WithECDSA";
            case EC_P521 -> "SHA512WithECDSA";
            case ED25519 -> "Ed25519";
            default -> throw new IllegalArgumentException("Algorithm not suitable for signing: " + algorithm);
        };
    }
}
