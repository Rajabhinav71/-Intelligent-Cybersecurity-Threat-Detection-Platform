package com.sentinelx.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "threat_alerts")
public class ThreatAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;

    @Column(name = "ip_address", nullable = false)
    private String ipAddress;

    @Column(name = "attack_type", nullable = false)
    private String attackType;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Column(name = "action_taken", nullable = false)
    private String actionTaken;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public ThreatAlert() {}

    public ThreatAlert(String username, String ip, String type, int score, String action) {
        this.username = username;
        this.ipAddress = ip;
        this.attackType = type;
        this.riskScore = score;
        this.actionTaken = action;
    }

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }

    public Long getId()              { return id; }
    public String getUsername()      { return username; }
    public String getIpAddress()     { return ipAddress; }
    public String getAttackType()    { return attackType; }
    public int getRiskScore()        { return riskScore; }
    public String getActionTaken()   { return actionTaken; }
    public LocalDateTime getCreatedAt() { return createdAt; }

    public void setId(Long id)               { this.id = id; }
    public void setUsername(String u)        { this.username = u; }
    public void setIpAddress(String ip)      { this.ipAddress = ip; }
    public void setAttackType(String t)      { this.attackType = t; }
    public void setRiskScore(int s)          { this.riskScore = s; }
    public void setActionTaken(String a)     { this.actionTaken = a; }
    public void setCreatedAt(LocalDateTime t){ this.createdAt = t; }
}
