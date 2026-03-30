package com.aikms.audit.repository;

import com.aikms.audit.domain.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    Page<AuditLog> findByNamespaceId(String namespaceId, Pageable pageable);

    Page<AuditLog> findByResourceTypeAndResourceId(String resourceType, String resourceId, Pageable pageable);

    Page<AuditLog> findByActorId(String actorId, Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE a.namespaceId = :nsId AND a.occurredAt BETWEEN :from AND :to ORDER BY a.occurredAt DESC")
    Page<AuditLog> findByNamespaceAndPeriod(String nsId, Instant from, Instant to, Pageable pageable);
}
