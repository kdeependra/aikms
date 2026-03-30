package com.aikms.kms.repository;

import com.aikms.kms.domain.KeyVersion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface KeyVersionRepository extends JpaRepository<KeyVersion, UUID> {

    @Query("SELECT kv FROM KeyVersion kv WHERE kv.key.keyId = :keyId " +
           "AND kv.versionNumber = (SELECT MAX(kv2.versionNumber) FROM KeyVersion kv2 WHERE kv2.key.keyId = :keyId)")
    Optional<KeyVersion> findLatestByKeyId(@Param("keyId") UUID keyId);

    Optional<KeyVersion> findByKey_KeyIdAndVersionNumber(UUID keyId, int versionNumber);
}
