"""
SentinelX Attack Simulator
───────────────────────────
Run this during the hackathon demo to show the dashboard lighting up in real time.

Usage:
  python simulator.py                    # run all attacks
  python simulator.py brute              # brute force only
  python simulator.py sqli               # SQL injection only
  python simulator.py ddos               # rate limit test only

Requirements: pip install requests
Target:       Spring Boot running on localhost:8080
"""

import requests
import time
import sys
import threading

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

BASE_URL = "http://localhost:8080"
LOGIN_URL = f"{BASE_URL}/api/auth/login"

# Simulate a slow human-like delay
def slow(): time.sleep(0.3)
def fast(): time.sleep(0.05)


# ── Attack 1: Brute Force ─────────────────────────────────────
def brute_force(username="admin", attempts=8):
    print(f"\n[ATTACK] Brute force on account '{username}' — {attempts} attempts")
    passwords = ["123456", "password", "qwerty", "admin", "letmein",
                 "welcome", "monkey", "dragon", "abc123", "master"]
    for i, pwd in enumerate(passwords[:attempts]):
        r = requests.post(LOGIN_URL, json={"username": username, "password": pwd},
                          headers={"X-Forwarded-For": "192.168.1.100"})
        status = r.status_code
        print(f"  Attempt {i+1}: password='{pwd}' → HTTP {status}")
        fast()
    print("[ATTACK] Brute force complete.")


# ── Attack 2: Credential Stuffing ────────────────────────────
def credential_stuffing():
    print("\n[ATTACK] Credential stuffing — trying many usernames from same IP")
    usernames = ["john", "sarah", "mike", "emma", "david", "lisa",
                 "tom", "kate", "james", "anna", "alex", "chris"]
    for user in usernames:
        r = requests.post(LOGIN_URL, json={"username": user, "password": "password123"},
                          headers={"X-Forwarded-For": "10.0.0.55"})
        print(f"  Trying '{user}' → HTTP {r.status_code}")
        fast()
    print("[ATTACK] Credential stuffing complete.")


# ── Attack 3: SQL Injection ───────────────────────────────────
def sql_injection():
    print("\n[ATTACK] SQL injection attempts")
    payloads = [
        "' OR '1'='1",
        "admin' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM users --",
        "1' AND 1=1 --",
    ]
    for p in payloads:
        r = requests.post(LOGIN_URL, json={"username": p, "password": "anything"},
                          headers={"X-Forwarded-For": "172.16.0.22"})
        print(f"  Payload: {p[:40]!r} → HTTP {r.status_code}")
        slow()
    print("[ATTACK] SQL injection complete.")


# ── Attack 4: XSS Attempt ────────────────────────────────────
def xss_attack():
    print("\n[ATTACK] XSS injection attempts")
    payloads = [
        "<script>alert('XSS')</script>",
        "<img onerror=alert(1) src=x>",
        "javascript:void(document.cookie)",
        "<iframe src='javascript:alert(1)'>",
    ]
    for p in payloads:
        r = requests.post(LOGIN_URL, json={"username": p, "password": "test"},
                          headers={"X-Forwarded-For": "172.16.0.33"})
        print(f"  Payload: {p[:40]!r} → HTTP {r.status_code}")
        slow()
    print("[ATTACK] XSS complete.")


# ── Attack 5: DDoS / Rate Flooding ───────────────────────────
def ddos_flood(count=120):
    print(f"\n[ATTACK] DDoS simulation — {count} rapid requests from same IP")
    success = 0
    blocked = 0
    for i in range(count):
        try:
            r = requests.post(LOGIN_URL,
                              json={"username": "victim", "password": "wrong"},
                              headers={"X-Forwarded-For": "203.0.113.99"},
                              timeout=2)
            if r.status_code == 403:
                blocked += 1
            else:
                success += 1
        except:
            blocked += 1
    print(f"  Results: {success} passed, {blocked} blocked")
    print("[ATTACK] DDoS simulation complete.")


# ── Attack 6: Scanner user-agent ─────────────────────────────
def scanner_detection():
    print("\n[ATTACK] Sending known scanner user-agents")
    scanners = [
        ("sqlmap/1.7", "SQLmap"),
        ("nikto/2.1.6", "Nikto"),
        ("DirBuster-1.0-RC1", "DirBuster"),
        ("Hydra v9.4", "Hydra"),
    ]
    for ua, name in scanners:
        r = requests.post(LOGIN_URL, json={"username": "test", "password": "test"},
                          headers={"User-Agent": ua,
                                   "X-Forwarded-For": "198.51.100.5"})
        print(f"  {name} (UA: {ua}) → HTTP {r.status_code}")
        slow()
    print("[ATTACK] Scanner detection complete.")


# ── Run all attacks ───────────────────────────────────────────
def run_all():
    print("=" * 55)
    print("  SentinelX Attack Simulator — starting demo attacks")
    print("=" * 55)
    print("Watch your dashboard at: http://localhost:8080/dashboard")

    brute_force("admin", 8)
    time.sleep(1)
    credential_stuffing()
    time.sleep(1)
    sql_injection()
    time.sleep(1)
    xss_attack()
    time.sleep(1)
    ddos_flood(120)
    time.sleep(1)
    scanner_detection()

    print("\n" + "=" * 55)
    print("  All attacks complete. Check your dashboard!")
    print("=" * 55)


# ── Entry point ───────────────────────────────────────────────
if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    handlers = {
        "brute":   lambda: brute_force("admin", 8),
        "cred":    credential_stuffing,
        "sqli":    sql_injection,
        "xss":     xss_attack,
        "ddos":    ddos_flood,
        "scanner": scanner_detection,
        "all":     run_all,
    }
    fn = handlers.get(mode, run_all)
    fn()
