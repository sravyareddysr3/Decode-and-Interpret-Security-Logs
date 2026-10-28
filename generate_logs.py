#!/usr/bin/env python3
"""Generate a sanitized, synthetic authentication log (auth_logs.csv).

Everything here is fictional: users are made up, and all IPs come from the
RFC 5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24),
which are reserved and never routable. Timestamps are in IST (local time of
the fictional company). The seed is fixed so results are reproducible.

The log contains ~7 days of mostly normal behaviour plus a handful of
deliberately seeded anomalies (and a couple of benign decoys), so the analysis
script has something real to find and to correctly *not* over-flag.
"""
import csv
import datetime as dt
import random

random.seed(42)

START = dt.datetime(2026, 10, 19, 0, 0, 0)  # Monday
DAYS = 7

USERS = ["asharma", "dpatel", "jroy", "mkhan", "tnair", "lfernandes", "rgupta",
         "snair", "vsingh", "kiyer", "pmehta", "nrao", "bdas", "hjoshi",
         "cthomas", "adesai", "ykumar", "sbose", "mreddy", "admin"]
SERVICE = "svc_backup"

OFFICE_IPS = [f"203.0.113.{i}" for i in range(10, 40)]
HOME_IPS = {u: f"203.0.113.{100 + i}" for i, u in enumerate(USERS)}  # all in-country ISP
BROWSERS = ["Chrome/118 Win10", "Chrome/118 macOS", "Firefox/119 Win10", "Edge/118 Win10"]
USER_BROWSER = {u: random.choice(BROWSERS) for u in USERS}

events = []


def add(ts, user, ip, country, event, agent, reason=""):
    events.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "user": user, "src_ip": ip, "country": country,
        "event": event, "user_agent": agent, "reason": reason,
        "_ts": ts,
    })


def at(day, hour, minute=0, second=0):
    return START + dt.timedelta(days=day, hours=hour, minutes=minute, seconds=second)


# ------------------------------------------------------------------ normal behaviour
for day in range(DAYS):
    weekday = (START + dt.timedelta(days=day)).weekday() < 5
    for u in USERS:
        agent = USER_BROWSER[u]
        if weekday:
            n = random.randint(3, 7)
            for _ in range(n):
                h = min(18, max(9, int(random.gauss(13, 2.5))))
                ts = at(day, h, random.randint(0, 59), random.randint(0, 59))
                ip = random.choice(OFFICE_IPS) if random.random() < 0.8 else HOME_IPS[u]
                if random.random() < 0.04:  # ordinary typo
                    add(ts, u, ip, "IN", "LOGIN_FAILURE", agent, "wrong_password")
                    ts += dt.timedelta(seconds=random.randint(10, 40))
                add(ts, u, ip, "IN", "LOGIN_SUCCESS", agent)
        elif random.random() < 0.05:  # rare weekend login
            ts = at(day, random.randint(10, 12), random.randint(0, 59))
            add(ts, u, HOME_IPS[u], "IN", "LOGIN_SUCCESS", agent)

    # nightly backup job - non-interactive agent at 01:00
    add(at(day, 1, random.randint(0, 3), random.randint(0, 59)), SERVICE,
        "203.0.113.5", "IN", "LOGIN_SUCCESS", "backup-agent/2.1")

# ------------------------------------------------------------------ seeded anomalies
# A1: brute force against 'admin' from one external IP, ends in success, then privilege grant
ip, c = "198.51.100.23", "RU"
t = at(2, 3, 10)  # Wednesday 03:10
for i in range(140):
    add(t + dt.timedelta(seconds=i * 6 + random.randint(0, 3)), "admin", ip, c,
        "LOGIN_FAILURE", "python-requests/2.31", "wrong_password")
add(t + dt.timedelta(minutes=16), "admin", ip, c, "LOGIN_SUCCESS", "python-requests/2.31")
add(t + dt.timedelta(minutes=21), "admin", ip, c, "PRIV_GRANT", "python-requests/2.31",
    "granted role=domain_admin to user=svc_tmp01")

# A2: password spraying - one IP, many users, 1-2 tries each, one success
ip, c = "192.0.2.77", "BR"
t = at(3, 14, 0)  # Thursday 14:00
targets = USERS + ["testuser", "hr", "finance", "backup"]  # last four don't exist
for i, u in enumerate(targets):
    for k in range(random.randint(1, 2)):
        add(t + dt.timedelta(seconds=i * 70 + k * 25), u, ip, c, "LOGIN_FAILURE",
            "Chrome/118 Win10",
            "unknown_user" if u in ("testuser", "hr", "finance", "backup") else "wrong_password")
add(t + dt.timedelta(minutes=33), "dpatel", ip, c, "LOGIN_SUCCESS", "Chrome/118 Win10")

# A3: impossible travel
add(at(1, 10, 5), "asharma", "203.0.113.12", "IN", "LOGIN_SUCCESS", USER_BROWSER["asharma"])
add(at(1, 10, 22), "asharma", "198.51.100.140", "DE", "LOGIN_SUCCESS", "Chrome/118 Win10")

# A4: MFA fatigue - repeated push denials then an approval
t = at(4, 11, 40)  # Friday
for i in range(12):
    add(t + dt.timedelta(seconds=i * 45), "tnair", "192.0.2.150", "CN", "MFA_DENIED",
        "Firefox/119 Win10", "push_rejected_by_user")
add(t + dt.timedelta(minutes=10), "tnair", "192.0.2.150", "CN", "LOGIN_SUCCESS", "Firefox/119 Win10")

# A5: service account used interactively from a new IP
add(at(5, 16, 14), SERVICE, "198.51.100.88", "NL", "LOGIN_SUCCESS", "Chrome/118 Win10")

# A6: scripted client for an ordinary user
add(at(3, 9, 30), "lfernandes", "203.0.113.20", "IN", "LOGIN_SUCCESS", "python-requests/2.31")

# ------------------------------------------------------------------ benign decoys
# D1: off-hours login from the user's own home IP (e.g. on-call), Saturday 02:47
add(at(5, 2, 47), "mkhan", HOME_IPS["mkhan"], "IN", "LOGIN_SUCCESS", USER_BROWSER["mkhan"])
# D2: lockout after forgotten password, then a password change, from a known IP
t = at(2, 9, 15)
for i in range(5):
    add(t + dt.timedelta(seconds=i * 20), "jroy", "203.0.113.15", "IN", "LOGIN_FAILURE",
        USER_BROWSER["jroy"], "wrong_password")
add(t + dt.timedelta(seconds=110), "jroy", "203.0.113.15", "IN", "ACCOUNT_LOCKED",
    USER_BROWSER["jroy"], "5_failed_attempts")
add(t + dt.timedelta(minutes=14), "jroy", "203.0.113.15", "IN", "PASSWORD_CHANGE",
    USER_BROWSER["jroy"], "helpdesk_reset")
add(t + dt.timedelta(minutes=15), "jroy", "203.0.113.15", "IN", "LOGIN_SUCCESS", USER_BROWSER["jroy"])

# ------------------------------------------------------------------ write out
events.sort(key=lambda e: e["_ts"])
with open("auth_logs.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["timestamp", "user", "src_ip", "country",
                                      "event", "user_agent", "reason"])
    w.writeheader()
    for e in events:
        w.writerow({k: v for k, v in e.items() if not k.startswith("_")})

print(f"wrote auth_logs.csv with {len(events)} events")
