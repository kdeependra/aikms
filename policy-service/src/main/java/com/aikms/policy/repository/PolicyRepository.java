package com.aikms.policy.repository;

import com.aikms.policy.domain.Policy;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PolicyRepository extends JpaRepository<Policy, UUID> {
    List<Policy> findByEnabled(boolean enabled);
    List<Policy> findByNamespaceId(UUID namespaceId);
    Optional<Policy> findByNamespaceIdAndName(UUID namespaceId, String name);
}
