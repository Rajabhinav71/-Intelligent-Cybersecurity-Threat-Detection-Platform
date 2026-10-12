package com.sentinelx.repository;

import com.sentinelx.model.ThreatAlert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ThreatAlertRepository extends JpaRepository<ThreatAlert, Long> {
    List<ThreatAlert> findTop50ByOrderByCreatedAtDesc();
    long countByAttackType(String attackType);
}
