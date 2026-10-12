package com.sentinelx.repository;

import com.sentinelx.model.BlockedIP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface BlockedIPRepository extends JpaRepository<BlockedIP, Long> {
    Optional<BlockedIP> findByIpAddress(String ipAddress);
    boolean existsByIpAddress(String ipAddress);
}
