package com.sentinelx.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "blocked_ips")
public class BlockedIP {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, unique = true)
    private String ipAddress;

    @Column(nullable = false)
    private String reason;

    @Column(name = "blocked_until")
    private LocalDateTime blockedUntil;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public BlockedIP() {}

    public BlockedIP(String ip, String reason, LocalDateTime until) {
        this.ipAddress = ip;
        this.reason = reason;
        this.blockedUntil = until;
    }

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }

    public Long getId()                      { return id; }
    public String getIpAddress()             { return ipAddress; }
    public String getReason()                { return reason; }
    public LocalDateTime getBlockedUntil()   { return blockedUntil; }
    public LocalDateTime getCreatedAt()      { return createdAt; }

    public void setId(Long id)               { this.id = id; }
    public void setIpAddress(String ip)      { this.ipAddress = ip; }
    public void setReason(String r)          { this.reason = r; }
    public void setBlockedUntil(LocalDateTime t){ this.blockedUntil = t; }
    public void setCreatedAt(LocalDateTime t){ this.createdAt = t; }
}
