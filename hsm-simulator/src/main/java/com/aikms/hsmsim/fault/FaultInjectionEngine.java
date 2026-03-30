package com.aikms.hsmsim.fault;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Fault injection engine for chaos testing.
 *
 * Each operation type can have a configured failure rate (0.0–1.0) and
 * optional artificial latency to simulate a slow HSM.
 *
 * Configuration is hot-reloadable via the /api/faults endpoint.
 */
@Slf4j
@Component
public class FaultInjectionEngine {

    @Getter @Setter
    private boolean enabled = false;

    /** operation → probability of failure (0.0 = never, 1.0 = always) */
    private final Map<String, Double> failureRates = new ConcurrentHashMap<>();

    /** operation → additional latency in milliseconds */
    private final Map<String, Long> latencyMs = new ConcurrentHashMap<>();

    // ─── Fault check ─────────────────────────────────────────────────────────────

    public void maybeFail(String operation) {
        if (!enabled) return;

        Double rate = failureRates.getOrDefault(operation, 0.0);
        if (rate > 0 && ThreadLocalRandom.current().nextDouble() < rate) {
            log.warn("[FAULT] Injected failure for operation: {}", operation);
            throw new RuntimeException("HSM fault injected for: " + operation);
        }

        Long latency = latencyMs.getOrDefault(operation, 0L);
        if (latency > 0) {
            log.debug("[FAULT] Injecting {}ms latency for: {}", latency, operation);
            try { Thread.sleep(latency); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }

    // ─── Configuration API (called by InspectionController) ───────────────────────

    public void setFailureRate(String operation, double rate) {
        failureRates.put(operation, rate);
        log.info("Fault rate set: operation={} rate={}", operation, rate);
    }

    public void setLatency(String operation, long ms) {
        latencyMs.put(operation, ms);
        log.info("Fault latency set: operation={} ms={}", operation, ms);
    }

    public void clearAll() {
        failureRates.clear();
        latencyMs.clear();
        log.info("All fault rules cleared");
    }

    public Map<String, Object> status() {
        return Map.of(
                "enabled",      enabled,
                "failureRates", Map.copyOf(failureRates),
                "latencyMs",    Map.copyOf(latencyMs)
        );
    }
}
