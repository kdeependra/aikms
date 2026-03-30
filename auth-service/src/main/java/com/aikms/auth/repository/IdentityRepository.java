package com.aikms.auth.repository;

import com.aikms.auth.domain.Identity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface IdentityRepository extends JpaRepository<Identity, UUID> {
    Optional<Identity> findByUsername(String username);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
