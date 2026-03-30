package com.aikms.hsmsim.crypto;

import com.aikms.hsmsim.fault.FaultInjectionEngine;
import com.aikms.hsmsim.slot.SlotRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Crypto engine that drives all HSM operations.
 *
 * Uses BouncyCastle as the JCA provider for AES-GCM, RSA-PKCS1, and EC.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CryptoEngine {

    private static final int GCM_IV_BYTES    = 12;
    private static final int GCM_TAG_BITS    = 128;
    private static final SecureRandom RNG    = new SecureRandom();

    private final SlotRegistry         slotRegistry;
    private final FaultInjectionEngine faultEngine;

    // ─── Key generation ───────────────────────────────────────────────────────────

    public String generateSymmetricKey(String algorithm, int keySizeBits) throws Exception {
        faultEngine.maybeFail("generateKey");
        KeyGenerator kg = KeyGenerator.getInstance("AES", "BC");
        kg.init(keySizeBits, RNG);
        SecretKey key = kg.generateKey();
        return slotRegistry.storeSecretKey(key, algorithm);
    }

    public String[] generateKeyPair(String algorithm, int keySizeBits) throws Exception {
        faultEngine.maybeFail("generateKeyPair");
        KeyPairGenerator kpg;
        if (algorithm.startsWith("EC") || algorithm.startsWith("Ed")) {
            kpg = KeyPairGenerator.getInstance("EC", "BC");
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(ecCurveFor(algorithm));
            kpg.initialize(spec, RNG);
        } else if (algorithm.startsWith("Ed25519")) {
            kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        } else {
            kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(keySizeBits, RNG);
        }
        KeyPair kp = kpg.generateKeyPair();
        String handle = slotRegistry.storeKeyPair(kp, algorithm);
        byte[] pubKeyBytes = kp.getPublic().getEncoded();
        return new String[]{ handle, HexFormat.of().formatHex(pubKeyBytes) };
    }

    // ─── Encrypt ─────────────────────────────────────────────────────────────────

    public byte[][] encrypt(String handle, byte[] plaintext) throws Exception {
        faultEngine.maybeFail("encrypt");
        SecretKey key = slotRegistry.getSecretKey(handle);

        byte[] iv = new byte[GCM_IV_BYTES];
        RNG.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] output = cipher.doFinal(plaintext);

        // GCM output = ciphertext || tag (last 16 bytes)
        int  tagOffset  = output.length - 16;
        byte[] ciphertext = Arrays.copyOf(output, tagOffset);
        byte[] tag        = Arrays.copyOfRange(output, tagOffset, output.length);

        return new byte[][]{ iv, ciphertext, tag };
    }

    // ─── Decrypt ─────────────────────────────────────────────────────────────────

    public byte[] decrypt(String handle, byte[] ciphertext, byte[] iv, byte[] tag) throws Exception {
        faultEngine.maybeFail("decrypt");
        SecretKey key = slotRegistry.getSecretKey(handle);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        // Reconstitute ciphertext || tag
        byte[] combined = Arrays.copyOf(ciphertext, ciphertext.length + tag.length);
        System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
        return cipher.doFinal(combined);
    }

    // ─── Wrap (encrypt a DEK under a KEK) ─────────────────────────────────────────

    public byte[][] wrapKey(String kekHandle, byte[] rawDek) throws Exception {
        return encrypt(kekHandle, rawDek);
    }

    // ─── Sign ─────────────────────────────────────────────────────────────────────

    public byte[] sign(String handle, byte[] data) throws Exception {
        faultEngine.maybeFail("sign");
        KeyPair kp = slotRegistry.getKeyPair(handle);
        String  alg = slotRegistry.getAlgorithm(handle);

        Signature sig = Signature.getInstance(signatureAlgorithmFor(alg), "BC");
        sig.initSign(kp.getPrivate(), RNG);
        sig.update(data);
        return sig.sign();
    }

    // ─── Verify ──────────────────────────────────────────────────────────────────

    public boolean verify(String handle, byte[] data, byte[] signature) throws Exception {
        faultEngine.maybeFail("verify");
        KeyPair kp = slotRegistry.getKeyPair(handle);
        String  alg = slotRegistry.getAlgorithm(handle);

        Signature sig = Signature.getInstance(signatureAlgorithmFor(alg), "BC");
        sig.initVerify(kp.getPublic());
        sig.update(data);
        return sig.verify(signature);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    private String ecCurveFor(String algorithm) {
        return switch (algorithm) {
            case "EC_P256" -> "P-256";
            case "EC_P384" -> "P-384";
            case "EC_P521" -> "P-521";
            default -> "P-256";
        };
    }

    private String signatureAlgorithmFor(String algorithm) {
        return switch (algorithm) {
            case "RSA_2048", "RSA_3072", "RSA_4096" -> "SHA256withRSA";
            case "EC_P256" -> "SHA256withECDSA";
            case "EC_P384" -> "SHA384withECDSA";
            case "EC_P521" -> "SHA512withECDSA";
            case "Ed25519"  -> "Ed25519";
            default -> "SHA256withECDSA";
        };
    }
}
