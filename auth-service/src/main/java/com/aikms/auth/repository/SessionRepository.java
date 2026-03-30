package com.aikms.auth.repository;

import com.aikms.auth.domain.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface SessionRepository extends JpaRepository<Session, UUID> {
    Optional<Session> findByJti(String jti);
    boolean existsByJtiAndRevokedFalse(String jti);

    @Modifying
    @Query("UPDATE Session s SET s.revoked = true, s.revokedAt = :now WHERE s.identityId = :identityId AND s.revoked = false")
    void revokeAllForIdentity(UUID identityId, Instant now);

    @Modifying
    @Query("DELETE FROM Session s WHERE s.expiresAt < :cutoff")
    void deleteExpiredSessions(Instant cutoff);
}
