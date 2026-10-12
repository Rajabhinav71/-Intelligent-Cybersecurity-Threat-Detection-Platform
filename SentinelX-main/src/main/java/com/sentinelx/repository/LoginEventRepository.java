// ─── LoginEventRepository.java ───────────────────────────────
package com.sentinelx.repository;

import com.sentinelx.model.LoginEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface LoginEventRepository extends JpaRepository<LoginEvent, Long> {

    // Count failed logins from an IP in the last N minutes
    @Query("SELECT COUNT(e) FROM LoginEvent e WHERE e.ipAddress = :ip " +
           "AND e.success = false AND e.createdAt >= :since")
    long countFailedByIpSince(@Param("ip") String ip,
                               @Param("since") LocalDateTime since);

    // Count failed logins for a specific username in the last N minutes
    @Query("SELECT COUNT(e) FROM LoginEvent e WHERE e.username = :username " +
           "AND e.success = false AND e.createdAt >= :since")
    long countFailedByUsernameSince(@Param("username") String username,
                                     @Param("since") LocalDateTime since);

    // Count distinct usernames tried from same IP (credential stuffing detection)
    @Query("SELECT COUNT(DISTINCT e.username) FROM LoginEvent e " +
           "WHERE e.ipAddress = :ip AND e.createdAt >= :since")
    long countDistinctUsernamesByIpSince(@Param("ip") String ip,
                                          @Param("since") LocalDateTime since);

    // Get all events from an IP for ML feature extraction
    List<LoginEvent> findByIpAddressAndCreatedAtAfter(String ip, LocalDateTime since);

    // For dashboard: last 100 events
    List<LoginEvent> findTop100ByOrderByCreatedAtDesc();
}
