package com.aikms.hsmsim.slot;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.*;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * In-memory slot registry that emulates a Hardware Security Module's key store.
 *
 * Slots contain SecretKey (symmetric) or KeyPair (asymmetric) objects,
 * indexed by an opaque handle.  Handles are never predictable.
 *
 * The registry intentionally stores keys only in JVM heap — no persistence.
 * This models the volatile nature of an HSM partition across restarts.
 */
@Slf4j
@Component
public class SlotRegistry {

    private static final SecureRandom RNG = new SecureRandom();

    /** handle → key material */
    private final Map<String, Object>  keyStore    = new ConcurrentHashMap<>();
    private final Map<String, String>  handleMeta  = new ConcurrentHashMap<>();  // handle → algorithm label
    private final AtomicInteger        handleSeq   = new AtomicInteger(1000);

    // ─── Store ────────────────────────────────────────────────────────────────────

    public String storeSecretKey(SecretKey key, String algorithm) {
        String handle = newHandle();
        keyStore.put(handle, key);
        handleMeta.put(handle, algorithm);
        log.debug("Stored symmetric key: handle={} alg={}", handle, algorithm);
        return handle;
    }

    public String storeKeyPair(KeyPair keyPair, String algorithm) {
        String handle = newHandle();
        keyStore.put(handle, keyPair);
        handleMeta.put(handle, algorithm);
        log.debug("Stored asymmetric key pair: handle={} alg={}", handle, algorithm);
        return handle;
    }

    // ─── Retrieve ─────────────────────────────────────────────────────────────────

    public SecretKey getSecretKey(String handle) {
        Object key = keyStore.get(handle);
        if (key == null) throw new IllegalArgumentException("Unknown handle: " + handle);
        if (!(key instanceof SecretKey)) throw new IllegalArgumentException("Handle is not a symmetric key: " + handle);
        return (SecretKey) key;
    }

    public KeyPair getKeyPair(String handle) {
        Object key = keyStore.get(handle);
        if (key == null) throw new IllegalArgumentException("Unknown handle: " + handle);
        if (!(key instanceof KeyPair)) throw new IllegalArgumentException("Handle is not a key pair: " + handle);
        return (KeyPair) key;
    }

    public boolean exists(String handle) {
        return keyStore.containsKey(handle);
    }

    public String getAlgorithm(String handle) {
        return handleMeta.get(handle);
    }

    // ─── Destroy ──────────────────────────────────────────────────────────────────

    public void destroy(String handle) {
        keyStore.remove(handle);
        handleMeta.remove(handle);
        log.info("Key destroyed: handle={}", handle);
    }

    // ─── Stats ────────────────────────────────────────────────────────────────────

    public int keyCount() { return keyStore.size(); }
    public Set<String> handles() { return keyStore.keySet(); }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    private String newHandle() {
        byte[] rand = new byte[8];
        RNG.nextBytes(rand);
        return "hsm-" + handleSeq.getAndIncrement() + "-"
                + java.util.HexFormat.of().formatHex(rand);
    }
}
