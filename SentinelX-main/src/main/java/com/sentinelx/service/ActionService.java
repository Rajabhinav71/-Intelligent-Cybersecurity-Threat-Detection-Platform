package com.sentinelx.service;

import com.sentinelx.model.BlockedIP;
import com.sentinelx.model.ThreatAlert;
import com.sentinelx.repository.BlockedIPRepository;
import com.sentinelx.repository.ThreatAlertRepository;
import com.sentinelx.service.DetectionService.DetectionResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.logging.Logger;

@Service
public class ActionService {

    private static final Logger log = Logger.getLogger(ActionService.class.getName());

    private final ThreatAlertRepository alertRepo;
    private final BlockedIPRepository blockedIPRepo;
    private final DetectionService detectionService;

    public ActionService(ThreatAlertRepository alertRepo,
                         BlockedIPRepository blockedIPRepo,
                         DetectionService detectionService) {
        this.alertRepo = alertRepo;
        this.blockedIPRepo = blockedIPRepo;
        this.detectionService = detectionService;
    }

    @Value("${sentinelx.risk.block-threshold:80}")
    private int blockThreshold;

    @Value("${sentinelx.risk.alert-threshold:50}")
    private int alertThreshold;

    public void respond(String username, String ip, DetectionResult result) {
        if (!result.isThreat()) return;

        String action;

        if (result.riskScore() >= blockThreshold) {
            if (result.blockIp()) {
                blockIp(ip, result.attackType());
                action = "IP_BLOCKED";
            } else {
                action = "ACCOUNT_LOCKED";
            }
            log.warning("[SENTINELX] HIGH RISK — " + username + " from " + ip
                + " — type: " + result.attackType() + " score: " + result.riskScore());
        } else if (result.riskScore() >= alertThreshold) {
            action = "ALERT_ONLY";
            log.info("[SENTINELX] ALERT — " + username + " from " + ip
                + " — type: " + result.attackType() + " score: " + result.riskScore());
        } else {
            return;
        }

        ThreatAlert alert = new ThreatAlert(username, ip, result.attackType(),
                                             result.riskScore(), action);
        alertRepo.save(alert);
    }

    public void blockIp(String ip, String reason) {
        if (!blockedIPRepo.existsByIpAddress(ip)) {
            BlockedIP block = new BlockedIP(ip, reason,
                                            LocalDateTime.now().plusHours(24));
            blockedIPRepo.save(block);
            log.warning("[SENTINELX] IP BLOCKED: " + ip + " — reason: " + reason);
        }
    }

    public boolean isBlocked(String ip) {
        return blockedIPRepo.findByIpAddress(ip)
            .map(b -> b.getBlockedUntil() == null ||
                      b.getBlockedUntil().isAfter(LocalDateTime.now()))
            .orElse(false);
    }

    @Scheduled(fixedRate = 60_000)
    public void cleanup() {
        detectionService.resetRequestCounters();
        blockedIPRepo.findAll().stream()
            .filter(b -> b.getBlockedUntil() != null &&
                         b.getBlockedUntil().isBefore(LocalDateTime.now()))
            .forEach(blockedIPRepo::delete);
    }
}
