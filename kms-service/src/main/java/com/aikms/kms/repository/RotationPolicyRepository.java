package com.aikms.kms.repository;

import com.aikms.kms.domain.RotationPolicy;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RotationPolicyRepository extends JpaRepository<RotationPolicy, UUID> {}
