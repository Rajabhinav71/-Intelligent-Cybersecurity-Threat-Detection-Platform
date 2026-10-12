package com.sentinelx.controller;

import com.sentinelx.model.LoginEvent;
import com.sentinelx.repository.LoginEventRepository;
import com.sentinelx.service.ActionService;
import com.sentinelx.service.DetectionService;
import com.sentinelx.service.DetectionService.DetectionResult;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final LoginEventRepository loginEventRepo;
    private final DetectionService detectionService;
    private final ActionService actionService;

    public AuthController(LoginEventRepository loginEventRepo,
                          DetectionService detectionService,
                          ActionService actionService) {
        this.loginEventRepo = loginEventRepo;
        this.detectionService = detectionService;
        this.actionService = actionService;
    }

    private static final Map<String, String> USERS = Map.of(
        "admin", "admin123",
        "alice", "password1",
        "bob",   "secret99"
    );

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestBody Map<String, String> body,
            HttpServletRequest request) {

        String username = body.getOrDefault("username", "").trim();
        String password = body.getOrDefault("password", "");
        String ip = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        boolean success = USERS.containsKey(username) &&
                          USERS.get(username).equals(password);

        LoginEvent event = new LoginEvent(username, ip, success, userAgent);
        loginEventRepo.save(event);

        DetectionResult result = detectionService.analyze(event);
        actionService.respond(username, ip, result);

        if (!success) {
            return ResponseEntity.status(401).body(Map.of(
                "status", "error",
                "message", "Invalid credentials",
                "threat_detected", result.isThreat(),
                "attack_type", result.attackType()
            ));
        }

        if (result.lockAccount()) {
            return ResponseEntity.status(423).body(Map.of(
                "status", "locked",
                "message", "Account temporarily locked due to suspicious activity."
            ));
        }

        return ResponseEntity.ok(Map.of(
            "status", "success",
            "message", "Login successful",
            "username", username
        ));
    }

    private String getClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return (forwarded != null) ? forwarded.split(",")[0].trim()
                                   : request.getRemoteAddr();
    }
}
