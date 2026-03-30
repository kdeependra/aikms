package com.aikms.kms.repository;

import com.aikms.common.domain.KeyState;
import com.aikms.kms.domain.Key;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface KeyRepository extends JpaRepository<Key, UUID> {

    Optional<Key> findByKeyIdAndNamespaceId(UUID keyId, UUID namespaceId);

    Page<Key> findByNamespaceId(UUID namespaceId, Pageable pageable);

    Page<Key> findByNamespaceIdAndState(UUID namespaceId, KeyState state, Pageable pageable);

    @Query("SELECT k FROM Key k WHERE k.namespaceId = :nsId AND k.state = 'ACTIVE' " +
           "AND k.expiresAt IS NOT NULL AND k.expiresAt <= :cutoff")
    List<Key> findExpiringSoon(@Param("nsId") UUID namespaceId, @Param("cutoff") Instant cutoff);

    @Query("SELECT k FROM Key k WHERE k.state = 'ACTIVE' " +
           "AND k.expiresAt IS NOT NULL AND k.expiresAt <= :cutoff")
    List<Key> findAllExpiringSoon(@Param("cutoff") Instant cutoff);

    @Query("SELECT k FROM Key k WHERE k.state = 'SCHEDULED_DESTROY' AND k.updatedAt <= :cutoff")
    List<Key> findReadyForDestruction(@Param("cutoff") Instant cutoff);

    boolean existsByNameAndNamespaceId(String name, UUID namespaceId);
}
