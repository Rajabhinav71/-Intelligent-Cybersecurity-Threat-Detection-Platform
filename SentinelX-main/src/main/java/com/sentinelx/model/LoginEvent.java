package com.sentinelx.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "login_events")
public class LoginEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;

    @Column(name = "ip_address", nullable = false)
    private String ipAddress;

    @Column(nullable = false)
    private boolean success;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "country_code")
    private String countryCode;

    @Column(name = "hour_of_day")
    private int hourOfDay;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    public LoginEvent() {}

    public LoginEvent(String username, String ipAddress, boolean success, String userAgent) {
        this.username = username;
        this.ipAddress = ipAddress;
        this.success = success;
        this.userAgent = userAgent;
    }

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.hourOfDay = createdAt.getHour();
    }

    public Long getId()                      { return id; }
    public String getUsername()              { return username; }
    public String getIpAddress()             { return ipAddress; }
    public boolean isSuccess()               { return success; }
    public String getUserAgent()             { return userAgent; }
    public String getCountryCode()           { return countryCode; }
    public int getHourOfDay()                { return hourOfDay; }
    public LocalDateTime getCreatedAt()      { return createdAt; }

    public void setId(Long id)               { this.id = id; }
    public void setUsername(String username) { this.username = username; }
    public void setIpAddress(String ip)      { this.ipAddress = ip; }
    public void setSuccess(boolean success)  { this.success = success; }
    public void setUserAgent(String ua)      { this.userAgent = ua; }
    public void setCountryCode(String cc)    { this.countryCode = cc; }
    public void setHourOfDay(int h)          { this.hourOfDay = h; }
    public void setCreatedAt(LocalDateTime t){ this.createdAt = t; }
}
