package com.aikms.policy.service;

import com.aikms.policy.domain.Policy;
import com.aikms.policy.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

/**
 * Policy evaluation service.
 *
 * Uses OPA's embedded Wasm evaluation or REST API.
 * For simplicity in development, policies are evaluated by calling the
 * OPA REST API at /v1/data/{package}.allow.
 *
 * In production, deploy OPA as a sidecar or use the embedded OPA library.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PolicyEvaluationService {

    private final PolicyRepository policyRepository;
    private final OpaClient        opaClient;

    /**
     * Evaluate whether the given input satisfies all enabled policies for a namespace.
     *
     * @param namespaceId  the tenant namespace
     * @param packagePath  OPA policy package (e.g. "aikms/key_access")
     * @param input        the input document (actor, resource, action)
     * @return true if the request is allowed by every applicable policy
     */
    public boolean evaluate(UUID namespaceId, String packagePath, Map<String, Object> input) {
        boolean result = opaClient.decide(packagePath, input);
        log.debug("Policy eval: ns={} pkg={} input={} result={}", namespaceId, packagePath, input, result);
        return result;
    }

    /**
     * Upsert a Rego policy into the running OPA instance, then persist the
     * source to the database for durability.
     */
    public void upsertPolicy(Policy policy) {
        opaClient.putPolicy("aikms/" + policy.getPolicyId(), policy.getRegoSource());
        policyRepository.save(policy);
    }

    /**
     * Reload all enabled namespace policies into OPA on startup or after failover.
     */
    public void reloadAll() {
        policyRepository.findByEnabled(true).forEach(p -> {
            try {
                opaClient.putPolicy("aikms/" + p.getPolicyId(), p.getRegoSource());
            } catch (Exception ex) {
                log.error("Failed to reload policy {}: {}", p.getPolicyId(), ex.getMessage());
            }
        });
    }
}
