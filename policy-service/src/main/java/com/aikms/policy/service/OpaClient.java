package com.aikms.policy.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Thin HTTP client for communicating with the OPA REST API.
 */
@Slf4j
@Component
public class OpaClient {

    private final WebClient webClient;

    public OpaClient(@Value("${aikms.opa.url:http://localhost:8181}") String baseUrl) {
        this.webClient = WebClient.builder()
                .baseUrl(baseUrl)
                .defaultStatusHandler(HttpStatusCode::isError,
                        r -> r.bodyToMono(String.class).flatMap(b -> Mono.error(new RuntimeException("OPA error: " + b))))
                .build();
    }

    /**
     * Evaluate the allow rule at the given package path.
     */
    @SuppressWarnings("unchecked")
    public boolean decide(String packagePath, Map<String, Object> input) {
        Map<String, Object> body = Map.of("input", input);
        String opaPath = "/v1/data/" + packagePath.replace('.', '/');

        Map<?, ?> resp = webClient.post().uri(opaPath)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(Map.class)
                .block();

        if (resp == null) return false;
        Object result = ((Map<?, ?>) resp.get("result"));
        if (result instanceof Map<?, ?> rm) {
            return Boolean.TRUE.equals(rm.get("allow"));
        }
        return Boolean.TRUE.equals(result);
    }

    /**
     * Upload or update a Rego policy into OPA.
     */
    public void putPolicy(String policyId, String regoSource) {
        webClient.put()
                .uri("/v1/policies/" + policyId)
                .bodyValue(regoSource)
                .retrieve()
                .toBodilessEntity()
                .block();
        log.debug("OPA policy upserted: {}", policyId);
    }
}
