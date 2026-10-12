package com.sentinelx.service;

import com.sentinelx.model.LoginEvent;
import com.sentinelx.repository.LoginEventRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

@Service
public class DetectionService {

    private static final Logger log = Logger.getLogger(DetectionService.class.getName());

    private final LoginEventRepository loginEventRepo;
    private final RestTemplate restTemplate;

    public DetectionService(LoginEventRepository loginEventRepo, RestTemplate restTemplate) {
        this.loginEventRepo = loginEventRepo;
        this.restTemplate = restTemplate;
    }

    @Value("${sentinelx.brute-force.max-attempts:5}")
    private int maxFailedAttempts;

    @Value("${sentinelx.brute-force.window-minutes:5}")
    private int windowMinutes;

    @Value("${sentinelx.ml.service-url:http://localhost:5000/predict}")
    private String mlServiceUrl;

    private final ConcurrentHashMap<String, Integer> requestCounter = new ConcurrentHashMap<>();

    public DetectionResult analyze(LoginEvent event) {
        String ip = event.getIpAddress();
        String username = event.getUsername();
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(windowMinutes);

        long failedByUser = loginEventRepo.countFailedByUsernameSince(username, windowStart);
        if (failedByUser >= maxFailedAttempts) {
            return new DetectionResult("BRUTE_FORCE", 90, true, false);
        }

        long distinctUsernames = loginEventRepo.countDistinctUsernamesByIpSince(ip, windowStart);
        if (distinctUsernames >= 10) {
            return new DetectionResult("CREDENTIAL_STUFF", 85, true, true);
        }

        long failedByIp = loginEventRepo.countFailedByIpSince(ip, windowStart);
        if (failedByIp >= maxFailedAttempts * 2) {
            return new DetectionResult("BRUTE_FORCE", 80, true, true);
        }

        int reqCount = requestCounter.getOrDefault(ip, 0);
        if (reqCount > 100) {
            return new DetectionResult("RATE_LIMIT", 75, false, true);
        }

        int mlScore = getAnomalyScore(event, failedByIp, reqCount);
        if (mlScore >= 70) {
            return new DetectionResult("ANOMALY", mlScore, false, false);
        }

        return new DetectionResult("NONE", 0, false, false);
    }

    private int getAnomalyScore(LoginEvent event, long failedLogins, int reqRate) {
        try {
            Map<String, Object> features = new HashMap<>();
            features.put("failed_logins", failedLogins);
            features.put("request_rate", reqRate);
            features.put("hour_of_day", event.getHourOfDay());
            features.put("login_success", event.isSuccess() ? 1 : 0);

            Map<?, ?> response = restTemplate.postForObject(mlServiceUrl, features, Map.class);
            if (response != null && response.containsKey("anomaly_score")) {
                return ((Number) response.get("anomaly_score")).intValue();
            }
        } catch (Exception e) {
            log.warning("ML service unavailable, using rules only: " + e.getMessage());
        }
        return 0;
    }

    public void incrementRequestCount(String ip) {
        requestCounter.merge(ip, 1, Integer::sum);
    }

    public void resetRequestCounters() {
        requestCounter.clear();
    }

    public record DetectionResult(
        String attackType,
        int riskScore,
        boolean lockAccount,
        boolean blockIp
    ) {
        public boolean isThreat() {
            return riskScore > 0;
        }
    }
}
