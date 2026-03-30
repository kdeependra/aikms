package com.aikms.kms.hsm;

import com.aikms.common.domain.KeyAlgorithm;
import com.aikms.common.exception.HsmUnavailableException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.HexFormat;
import java.util.Map;

/**
 * HsmProvider implementation that delegates to the HSM Simulator
 * over HTTP(S).  Uses Spring WebClient (blocking) for simplicity
 * since all callers are already in a virtual-thread context.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "aikms.hsm.provider", havingValue = "SIMULATOR")
public class HsmSimulatorProvider implements HsmProvider {

    private final WebClient client;

    public HsmSimulatorProvider(@Value("${aikms.hsm.simulator-url:http://localhost:8090}") String baseUrl) {
        this.client = WebClient.builder()
                .baseUrl(baseUrl)
                .defaultStatusHandler(HttpStatusCode::isError,
                        resp -> resp.bodyToMono(String.class)
                                .flatMap(msg -> Mono.error(new HsmUnavailableException("HSM error: " + msg))))
                .build();
    }

    // ─── Key generation ───────────────────────────────────────────────────────────

    @Override
    @Retry(name = "hsm") @CircuitBreaker(name = "hsm")
    public String generateSymmetricKey(KeyAlgorithm algorithm, int keySizeBits) {
        Map<?, ?> resp = post("/api/hsm/keys/symmetric",
                Map.of("algorithm", algorithm.name(), "keySizeBits", keySizeBits), Map.class);
        return (String) resp.get("handle");
    }

    @Override
    @Retry(name = "hsm") @CircuitBreaker(name = "hsm")
    public HsmKeyPairResult generateKeyPair(KeyAlgorithm algorithm) {
        Map<?, ?> resp = post("/api/hsm/keys/asymmetric",
                Map.of("algorithm", algorithm.name(), "keySizeBits", algorithm.getKeySizeBits()), Map.class);
        String handle     = (String) resp.get("handle");
        byte[] pubKeyBytes = HexFormat.of().parseHex((String) resp.get("publicKeyHex"));
        return new HsmKeyPairResult(handle, pubKeyBytes);
    }

    // ─── Crypto ───────────────────────────────────────────────────────────────────

    @Override
    @Retry(name = "hsm") @CircuitBreaker(name = "hsm")
    public EncryptResult encrypt(String handle, byte[] plaintext, KeyAlgorithm algorithm) {
        Map<?, ?> resp = post("/api/hsm/encrypt",
                Map.of("handle", handle != null ? handle : "", "plaintextHex", HexFormat.of().formatHex(plaintext)),
                Map.class);
        return new EncryptResult(
                HexFormat.of().parseHex((String) resp.get("ivHex")),
                HexFormat.of().parseHex((String) resp.get("ciphertextHex")),
                HexFormat.of().parseHex((String) resp.get("tagHex"))
        );
    }

    @Override
    @Retry(name = "hsm") @CircuitBreaker(name = "hsm")
    public byte[] decrypt(String handle, byte[] ciphertext, byte[] iv, KeyAlgorithm algorithm) {
        Map<?, ?> resp = post("/api/hsm/decrypt",
                Map.of(
                        "handle",        handle,
                        "ciphertextHex", HexFormat.of().formatHex(ciphertext),
                        "ivHex",         HexFormat.of().formatHex(iv),
                        "tagHex",        ""
                ), Map.class);
        return HexFormat.of().parseHex((String) resp.get("plaintextHex"));
    }

    @Override
    @Retry(name = "hsm") @CircuitBreaker(name = "hsm")
    public byte[] sign(String handle, byte[] data, KeyAlgorithm algorithm) {
        Map<?, ?> resp = post("/api/hsm/sign",
                Map.of("handle", handle, "dataHex", HexFormat.of().formatHex(data)), Map.class);
        return HexFormat.of().parseHex((String) resp.get("signatureHex"));
    }

    @Override
    @Retry(name = "hsm") @CircuitBreaker(name = "hsm")
    public boolean verify(String handle, byte[] data, byte[] signature, KeyAlgorithm algorithm) {
        Map<?, ?> resp = post("/api/hsm/verify",
                Map.of(
                        "handle",       handle,
                        "dataHex",      HexFormat.of().formatHex(data),
                        "signatureHex", HexFormat.of().formatHex(signature)
                ), Map.class);
        return Boolean.TRUE.equals(resp.get("valid"));
    }

    @Override
    @Retry(name = "hsm") @CircuitBreaker(name = "hsm")
    public EncryptResult wrapKey(String kekHandle, byte[] rawKeyBytes, KeyAlgorithm algorithm) {
        Map<?, ?> resp = post("/api/hsm/wrap",
                Map.of("kekHandle", kekHandle, "rawDekHex", HexFormat.of().formatHex(rawKeyBytes)), Map.class);
        return new EncryptResult(
                HexFormat.of().parseHex((String) resp.get("ivHex")),
                HexFormat.of().parseHex((String) resp.get("ciphertextHex")),
                HexFormat.of().parseHex((String) resp.get("tagHex"))
        );
    }

    @Override
    @Retry(name = "hsm") @CircuitBreaker(name = "hsm")
    public void destroyKey(String handle) {
        client.delete().uri("/api/hsm/keys/{handle}", handle)
                .retrieve().toBodilessEntity().block();
        log.info("Key destroyed in HSM simulator: handle={}", handle);
    }

    @Override
    public boolean healthCheck() {
        try {
            client.get().uri("/actuator/health")
                    .retrieve().toBodilessEntity().block();
            return true;
        } catch (Exception ex) {
            log.warn("HSM simulator health check failed: {}", ex.getMessage());
            return false;
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    private <T> T post(String path, Object body, Class<T> clazz) {
        return client.post().uri(path)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(clazz)
                .block();
    }
}
