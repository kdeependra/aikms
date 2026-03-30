package com.aikms.hsmsim.api;

import com.aikms.hsmsim.crypto.CryptoEngine;
import com.aikms.hsmsim.fault.FaultInjectionEngine;
import com.aikms.hsmsim.slot.SlotRegistry;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.HexFormat;
import java.util.Map;

@RestController
@RequestMapping("/api/hsm")
@RequiredArgsConstructor
public class HsmController {

    private final CryptoEngine         cryptoEngine;
    private final SlotRegistry         slotRegistry;
    private final FaultInjectionEngine faultEngine;

    // ─── Key generation ───────────────────────────────────────────────────────────

    @PostMapping("/keys/symmetric")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, String> generateSymmetric(@Valid @RequestBody GenerateSymmetricRequest req) throws Exception {
        String handle = cryptoEngine.generateSymmetricKey(req.algorithm(), req.keySizeBits());
        return Map.of("handle", handle);
    }

    @PostMapping("/keys/asymmetric")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, String> generateAsymmetric(@Valid @RequestBody GenerateAsymmetricRequest req) throws Exception {
        String[] result = cryptoEngine.generateKeyPair(req.algorithm(), req.keySizeBits());
        return Map.of("handle", result[0], "publicKeyHex", result[1]);
    }

    // ─── Crypto operations ────────────────────────────────────────────────────────

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(@Valid @RequestBody EncryptRequest req) throws Exception {
        byte[] pt = HexFormat.of().parseHex(req.plaintextHex());
        byte[][] result = cryptoEngine.encrypt(req.handle(), pt);
        return new EncryptResponse(
                HexFormat.of().formatHex(result[0]),   // iv
                HexFormat.of().formatHex(result[1]),   // ciphertext
                HexFormat.of().formatHex(result[2])    // tag
        );
    }

    @PostMapping("/decrypt")
    public Map<String, String> decrypt(@Valid @RequestBody DecryptRequest req) throws Exception {
        byte[] ct  = HexFormat.of().parseHex(req.ciphertextHex());
        byte[] iv  = HexFormat.of().parseHex(req.ivHex());
        byte[] tag = HexFormat.of().parseHex(req.tagHex());
        byte[] pt  = cryptoEngine.decrypt(req.handle(), ct, iv, tag);
        return Map.of("plaintextHex", HexFormat.of().formatHex(pt));
    }

    @PostMapping("/sign")
    public Map<String, String> sign(@Valid @RequestBody SignRequest req) throws Exception {
        byte[] data = HexFormat.of().parseHex(req.dataHex());
        byte[] sig  = cryptoEngine.sign(req.handle(), data);
        return Map.of("signatureHex", HexFormat.of().formatHex(sig));
    }

    @PostMapping("/verify")
    public Map<String, Boolean> verify(@Valid @RequestBody VerifyRequest req) throws Exception {
        byte[] data = HexFormat.of().parseHex(req.dataHex());
        byte[] sig  = HexFormat.of().parseHex(req.signatureHex());
        boolean valid = cryptoEngine.verify(req.handle(), data, sig);
        return Map.of("valid", valid);
    }

    @PostMapping("/wrap")
    public EncryptResponse wrapKey(@Valid @RequestBody WrapKeyRequest req) throws Exception {
        byte[] rawDek = HexFormat.of().parseHex(req.rawDekHex());
        byte[][] result = cryptoEngine.wrapKey(req.kekHandle(), rawDek);
        return new EncryptResponse(
                HexFormat.of().formatHex(result[0]),
                HexFormat.of().formatHex(result[1]),
                HexFormat.of().formatHex(result[2])
        );
    }

    // ─── Key destruction ──────────────────────────────────────────────────────────

    @DeleteMapping("/keys/{handle}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void destroyKey(@PathVariable String handle) {
        slotRegistry.destroy(handle);
    }

    // ─── Inspection / fault injection ─────────────────────────────────────────────

    @GetMapping("/status")
    public Map<String, Object> status() {
        return Map.of(
                "keyCount",   slotRegistry.keyCount(),
                "faultStatus", faultEngine.status()
        );
    }

    @PostMapping("/faults")
    public void configureFault(@RequestBody FaultConfig cfg) {
        faultEngine.setEnabled(cfg.enabled());
        if (cfg.failureRates() != null) {
            cfg.failureRates().forEach(faultEngine::setFailureRate);
        }
        if (cfg.latencyMs() != null) {
            cfg.latencyMs().forEach(faultEngine::setLatency);
        }
    }

    @DeleteMapping("/faults")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void clearFaults() {
        faultEngine.clearAll();
    }

    // ─── Request / Response records ──────────────────────────────────────────────

    public record GenerateSymmetricRequest(@NotBlank String algorithm, int keySizeBits) {}
    public record GenerateAsymmetricRequest(@NotBlank String algorithm, int keySizeBits) {}
    public record EncryptRequest(@NotBlank String handle, @NotBlank String plaintextHex) {}
    public record DecryptRequest(@NotBlank String handle, @NotBlank String ciphertextHex,
                                 @NotBlank String ivHex, @NotBlank String tagHex) {}
    public record SignRequest(@NotBlank String handle, @NotBlank String dataHex) {}
    public record VerifyRequest(@NotBlank String handle, @NotBlank String dataHex, @NotBlank String signatureHex) {}
    public record WrapKeyRequest(@NotBlank String kekHandle, @NotBlank String rawDekHex) {}
    public record EncryptResponse(String ivHex, String ciphertextHex, String tagHex) {}
    public record FaultConfig(boolean enabled, Map<String, Double> failureRates, Map<String, Long> latencyMs) {}
}
