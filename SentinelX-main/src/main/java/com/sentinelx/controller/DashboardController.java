package com.sentinelx.controller;

import com.sentinelx.model.BlockedIP;
import com.sentinelx.model.ThreatAlert;
import com.sentinelx.repository.BlockedIPRepository;
import com.sentinelx.repository.LoginEventRepository;
import com.sentinelx.repository.ThreatAlertRepository;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
@CrossOrigin(origins = "*")
public class DashboardController {

    private final ThreatAlertRepository alertRepo;
    private final BlockedIPRepository blockedIPRepo;
    private final LoginEventRepository loginEventRepo;

    public DashboardController(ThreatAlertRepository alertRepo,
                                BlockedIPRepository blockedIPRepo,
                                LoginEventRepository loginEventRepo) {
        this.alertRepo = alertRepo;
        this.blockedIPRepo = blockedIPRepo;
        this.loginEventRepo = loginEventRepo;
    }

    @GetMapping("/stats")
    public Map<String, Object> getStats() {
        return Map.of(
            "total_alerts",   alertRepo.count(),
            "blocked_ips",    blockedIPRepo.count(),
            "total_logins",   loginEventRepo.count(),
            "brute_force",    alertRepo.countByAttackType("BRUTE_FORCE"),
            "injections",     alertRepo.countByAttackType("INJECTION"),
            "rate_limit",     alertRepo.countByAttackType("RATE_LIMIT"),
            "anomaly",        alertRepo.countByAttackType("ANOMALY")
        );
    }

    @GetMapping("/alerts")
    public List<ThreatAlert> getAlerts() {
        return alertRepo.findTop50ByOrderByCreatedAtDesc();
    }

    @GetMapping("/blocked-ips")
    public List<BlockedIP> getBlockedIps() {
        return blockedIPRepo.findAll();
    }

    @GetMapping("/events")
    public Object getEvents() {
        return loginEventRepo.findTop100ByOrderByCreatedAtDesc();
    }

    @DeleteMapping("/blocked-ips/{id}")
    public Map<String, String> unblockIp(@PathVariable Long id) {
        blockedIPRepo.deleteById(id);
        return Map.of("status", "unblocked");
    }
}
