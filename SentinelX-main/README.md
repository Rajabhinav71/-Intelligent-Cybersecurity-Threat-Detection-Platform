# SentinelX — Smart Cyber Threat Detection System

A lightweight backend security layer that monitors web applications
for cyber threats in real time. Built with Spring Boot + Python ML.

---

## What it detects

| Attack                | How                                      |
|-----------------------|------------------------------------------|
| Brute force           | Failed login count rule (per user + IP)  |
| Credential stuffing   | Many usernames from one IP               |
| DDoS / rate abuse     | Requests-per-minute counter per IP       |
| SQL injection         | Regex pattern scan on all parameters     |
| XSS                   | Script/event-handler pattern scan        |
| Path traversal        | ../ and encoded variants                 |
| Scanner tools         | Known bad user-agents (sqlmap, nikto...) |
| Behavioural anomaly   | Isolation Forest ML model                |

---

## Project structure

```
sentinelx/
├── pom.xml                          Maven build file
├── src/main/java/com/sentinelx/
│   ├── SentinelXApplication.java    App entry point
│   ├── config/AppConfig.java        Spring beans
│   ├── filter/SentinelFilter.java   Intercepts every HTTP request
│   ├── model/                       JPA entities (DB tables)
│   │   ├── LoginEvent.java
│   │   ├── ThreatAlert.java
│   │   └── BlockedIP.java
│   ├── repository/                  DB query methods
│   │   ├── LoginEventRepository.java
│   │   ├── ThreatAlertRepository.java
│   │   └── BlockedIPRepository.java
│   ├── service/
│   │   ├── DetectionService.java    Core detection engine
│   │   └── ActionService.java       Block / lock / alert logic
│   └── controller/
│       ├── AuthController.java      POST /api/auth/login
│       └── DashboardController.java GET /api/dashboard/*
├── src/main/resources/
│   └── application.properties       DB + config settings
├── ml_service/
│   ├── app.py                       Flask REST API
│   ├── model.py                     Isolation Forest model
│   └── requirements.txt
├── dashboard/
│   └── index.html                   Admin dashboard (open in browser)
└── simulator/
    └── attack_simulator.py          Demo attack script
```

---

## Quick start (3 terminals)

### Terminal 1 — MySQL
```bash
# Start MySQL and create database
mysql -u root -p
CREATE DATABASE sentinelx;
EXIT;
```
Update `src/main/resources/application.properties` with your MySQL password.

### Terminal 2 — Python ML service
```bash
cd ml_service
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5000
```

### Terminal 3 — Spring Boot
```bash
# From project root
./mvnw spring-boot:run
# Runs on http://localhost:8080
```

### Open the dashboard
Open `dashboard/index.html` directly in your browser.

### Run the attack simulator (for demo)
```bash
cd simulator
pip install requests
python attack_simulator.py         # all attacks
python attack_simulator.py brute   # just brute force
python attack_simulator.py sqli    # just SQL injection
python attack_simulator.py ddos    # just DDoS flood
```

---

## API reference

### Auth endpoint (the one developers integrate)
```
POST /api/auth/login
Body: { "username": "alice", "password": "secret" }

Responses:
  200  { "status": "success" }
  401  { "status": "error", "message": "Invalid credentials" }
  403  Blocked by SentinelFilter (injection / bad IP)
  423  { "status": "locked" }  — account locked after brute force
```

### Dashboard endpoints
```
GET  /api/dashboard/stats          Summary counts
GET  /api/dashboard/alerts         Last 50 threat alerts
GET  /api/dashboard/blocked-ips    Currently blocked IPs
GET  /api/dashboard/events         Last 100 login events
DELETE /api/dashboard/blocked-ips/{id}   Unblock an IP
```

### ML service
```
POST http://localhost:5000/predict
Body: { "failed_logins": 3, "request_rate": 45,
        "hour_of_day": 2, "login_success": 0 }

Response: { "anomaly_score": 78, "is_anomaly": true }
```

---

## Configuration (application.properties)

```properties
sentinelx.brute-force.max-attempts=5       # lock after N failures
sentinelx.brute-force.window-minutes=5     # in this many minutes
sentinelx.rate-limit.max-requests-per-minute=100
sentinelx.risk.block-threshold=80          # block IP above this score
sentinelx.risk.alert-threshold=50          # alert above this score
sentinelx.ml.service-url=http://localhost:5000/predict
```

---

## Demo script (for judges)

1. Open the dashboard in browser — all stats at zero
2. Run: `python attack_simulator.py brute`
   - Watch the dashboard: threat cards appear, risk bars fill red
   - Show the "BRUTE_FORCE" badge and "IP_BLOCKED" action
3. Run: `python attack_simulator.py sqli`
   - Show injection attempts being blocked with HTTP 403
   - Dashboard shows "INJECTION" type alerts
4. Run: `python attack_simulator.py ddos`
   - 120 rapid requests — most get blocked
5. Show the Blocked IPs section — click unblock on one
6. Show the attack type pie chart has updated

Total demo time: ~3 minutes. Practice it twice before presenting.

---

## Team

Built at [Your College] Hackathon — February 11-12
Team: [Names]
