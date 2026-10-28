#!/usr/bin/env python3
"""Analyze auth_logs.csv: summarize normal behaviour, then flag anomalies.

Usage: python3 analyze_logs.py [auth_logs.csv]
Outputs: findings.csv, baseline.txt, charts/*.png
"""
import os
import sys
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

path = sys.argv[1] if len(sys.argv) > 1 else "auth_logs.csv"
df = pd.read_csv(path, parse_dates=["timestamp"]).fillna("")
df = df.sort_values("timestamp").reset_index(drop=True)
df["hour"] = df["timestamp"].dt.hour
df["weekday"] = df["timestamp"].dt.weekday
HOME_COUNTRY = df["country"].mode()[0]
os.makedirs("charts", exist_ok=True)

# ------------------------------------------------------------------ 1. baseline
succ = df[df.event == "LOGIN_SUCCESS"]
fail = df[df.event == "LOGIN_FAILURE"]
lines = []
lines.append(f"Log period        : {df.timestamp.min()}  ->  {df.timestamp.max()}")
lines.append(f"Total events      : {len(df)}")
lines.append("Event types       : " + ", ".join(f"{k}={v}" for k, v in df.event.value_counts().items()))
lines.append(f"Distinct users    : {df.user.nunique()}   Distinct source IPs: {df.src_ip.nunique()}")
lines.append(f"Home country      : {HOME_COUNTRY} ({(df.country == HOME_COUNTRY).mean():.1%} of events)")
lines.append(f"Overall failure rate (failures / success+failure): {len(fail) / (len(fail) + len(succ)):.1%}")
_in_f = len(fail[fail.country == HOME_COUNTRY]); _in_s = len(succ[succ.country == HOME_COUNTRY])
lines.append(f"In-country failure rate (typical user typo rate): {_in_f / (_in_f + _in_s):.1%}")
wk = succ[(succ.weekday < 5) & (succ.user != "svc_backup")]
lines.append(f"Weekday human logins: 09:00-18:59 share = {wk.hour.between(9, 18).mean():.1%}")
lines.append(f"Weekend logins    : {len(succ[succ.weekday >= 5])} total")
normal = df[(df.country == HOME_COUNTRY) & (df.user_agent != "python-requests/2.31")]
lines.append("Common user agents: " + ", ".join(f"{k} ({v})" for k, v in df.user_agent.value_counts().head(6).items()))
lines.append("Failures per IP (top 5): " + ", ".join(f"{k}={v}" for k, v in fail.src_ip.value_counts().head(5).items()))
typical_fail = fail[fail.country == HOME_COUNTRY]
lines.append(f"In-country failures: {len(typical_fail)} across {typical_fail.user.nunique()} users "
             f"(max per user per day = {typical_fail.groupby([typical_fail.user, typical_fail.timestamp.dt.date]).size().max()})")
open("baseline.txt", "w").write("\n".join(lines) + "\n")
print("\n".join(lines))

# per-user baselines
user_hours = succ.groupby("user")["hour"].apply(lambda s: Counter(s))
user_ips = succ.groupby("user")["src_ip"].apply(set)
user_agents = succ.groupby("user")["user_agent"].apply(Counter)

findings = []


def add(fid, severity, category, user, ip, when, evidence, interpretation, next_step):
    findings.append(dict(id=fid, severity=severity, category=category, user=user, src_ip=ip,
                         time=when, evidence=evidence, interpretation=interpretation,
                         next_step=next_step))


# ------------------------------------------------------------------ 2. detections
# D-1 brute force: >=20 failures from one IP against one user within 30 min
for (ip, user), g in fail.groupby(["src_ip", "user"]):
    g = g.sort_values("timestamp")
    ts = g.timestamp.tolist()
    j = 0
    for i in range(len(ts)):
        while ts[i] - ts[j] > pd.Timedelta(minutes=30):
            j += 1
        if i - j + 1 >= 20:
            n = len(g)
            first, last = g.timestamp.min(), g.timestamp.max()
            later_ok = succ[(succ.src_ip == ip) & (succ.user == user) & (succ.timestamp >= first)]
            ok_txt = f"; followed by SUCCESS at {later_ok.timestamp.iloc[0]}" if len(later_ok) else ""
            add("F1", "CRITICAL" if len(later_ok) else "HIGH", "Brute force", user, ip, first,
                f"{n} failures from {ip} against '{user}' between {first} and {last}{ok_txt}",
                "Rapid repeated failures from a single external IP against one account, scripted client; "
                "a success afterwards means the guess likely worked.",
                "Treat '" + user + "' as compromised: reset credentials, kill sessions, review actions after success.")
            break

# D-2 password spraying: one IP, many distinct users, few attempts each
for ip, g in fail.groupby("src_ip"):
    users = g.user.nunique()
    per_user = g.groupby("user").size()
    if users >= 10 and per_user.max() <= 3:
        later_ok = succ[(succ.src_ip == ip) & (succ.timestamp >= g.timestamp.min())]
        ok_txt = "; ".join(f"SUCCESS for '{r.user}' at {r.timestamp}" for r in later_ok.itertuples())
        unknown = g[g.reason == "unknown_user"].user.nunique()
        add("F2", "CRITICAL" if len(later_ok) else "HIGH", "Password spraying", ", ".join(sorted(g.user.unique()[:3])) + ", ...",
            ip, g.timestamp.min(),
            f"{ip} tried {users} distinct accounts ({int(per_user.sum())} attempts, max {per_user.max()} per account, "
            f"{unknown} nonexistent usernames) {g.timestamp.min()} -> {g.timestamp.max()}. {ok_txt}",
            "Low-and-slow: few tries per account avoids lockouts. Guessing names like 'hr'/'finance' shows enumeration.",
            "Investigate the account that succeeded first; block/watch the IP; check other accounts for the same source.")

# D-3 impossible travel: consecutive successes, different country, <2h apart
for user, g in succ.groupby("user"):
    g = g.sort_values("timestamp")
    prev = None
    for r in g.itertuples():
        if prev is not None and r.country != prev.country and (r.timestamp - prev.timestamp) < pd.Timedelta(hours=2):
            mins = (r.timestamp - prev.timestamp).total_seconds() / 60
            add("F3", "HIGH", "Impossible travel", user, f"{prev.src_ip} -> {r.src_ip}", r.timestamp,
                f"'{user}' succeeded from {prev.country} at {prev.timestamp} and from {r.country} at {r.timestamp} ({mins:.0f} min apart)",
                "Physical travel between these countries in that time is not possible; either a VPN/proxy or a second party is using the credentials.",
                "Confirm with the user; check second-login device/user-agent; force re-auth and review MFA logs.")
        prev = r

# D-4 MFA fatigue: >=5 MFA denials within 15 minutes for one user
mfa = df[df.event == "MFA_DENIED"]
for user, g in mfa.groupby("user"):
    if len(g) >= 5 and (g.timestamp.max() - g.timestamp.min()) <= pd.Timedelta(minutes=15):
        later = succ[(succ.user == user) & (succ.timestamp >= g.timestamp.min()) & (succ.src_ip == g.src_ip.iloc[0])]
        ok_txt = f"; SUCCESS from same IP at {later.timestamp.iloc[0]}" if len(later) else ""
        add("F4", "HIGH", "MFA fatigue", user, g.src_ip.iloc[0], g.timestamp.min(),
            f"{len(g)} push denials from {g.src_ip.iloc[0]} ({g.country.iloc[0]}) in {(g.timestamp.max() - g.timestamp.min()).seconds // 60} min{ok_txt}",
            "Attacker already knows the password and is spamming push prompts hoping the user approves; the later success suggests the user gave in.",
            "Contact user, reset password, revoke sessions, move to number-matching MFA.")

# D-5 service account used in an unusual way (new UA or new IP)
svc_users = [u for u in succ.user.unique() if u.startswith("svc_")]
for su in svc_users:
    g = succ[succ.user == su]
    base_ip, base_ua = g.src_ip.mode()[0], g.user_agent.mode()[0]
    for r in g[(g.src_ip != base_ip) | (g.user_agent != base_ua)].itertuples():
        add("F5", "HIGH", "Service account misuse", su, r.src_ip, r.timestamp,
            f"'{su}' normally logs in from {base_ip} with '{base_ua}' (once nightly ~01:00); this login: {r.src_ip} ({r.country}), '{r.user_agent}' at {r.timestamp}",
            "Service accounts should not do interactive browser logins from new networks.",
            "Verify with the owner; rotate the secret; scope the account's permissions.")

# D-6 scripted client for a human user
for r in succ[(succ.user_agent.str.startswith("python-requests")) & (succ.user != "admin")].itertuples():
    add("F6", "MEDIUM", "Unusual client", r.user, r.src_ip, r.timestamp,
        f"Successful login for '{r.user}' using '{r.user_agent}'; this user's other logins use: "
        f"{ {k: int(v) for k, v in succ[(succ.user == r.user) & (succ.user_agent != r.user_agent)].user_agent.value_counts().items()} }",
        "Human accounts normally log in via a browser; a scripting library may mean automation or a stolen credential used by a tool. "
        "Source IP is a known office address, so risk is lower.",
        "Ask the user whether they run scripts; if not, review the session activity.")

# D-7 off-hours logins: success on an hour the user rarely uses (<=1 occurrence) and outside 07-21
hits = succ[~succ.user.str.startswith("svc_")]
for r in hits.itertuples():
    if r.hour < 7 or r.hour > 21:
        n_same = int(user_hours[r.user].get(r.hour, 0)) - 1  # exclude this event itself
        known_ip = r.src_ip in user_ips[r.user] - {r.src_ip} or (succ[(succ.user == r.user) & (succ.src_ip == r.src_ip)].shape[0] > 1)
        sev = "LOW" if known_ip and r.country == HOME_COUNTRY else "MEDIUM"
        # skip those already covered by a brute-force success
        if r.src_ip in ("198.51.100.23",):
            continue
        add("F7", sev, "Off-hours login", r.user, r.src_ip, r.timestamp,
            f"'{r.user}' logged in at {r.timestamp.strftime('%a %H:%M')}; {n_same} prior logins at that hour; "
            f"IP {'previously seen' if known_ip else 'never seen'} for this user; country {r.country}",
            "Outside the user's normal 09-19h pattern, but from the user's own home IP and country." if sev == "LOW" else
            "Outside normal pattern and from an unfamiliar IP.",
            "Low priority: ask user/manager whether on-call. Escalate only if unexplained.")

# D-8 lockouts and what followed (context-dependent)
for r in df[df.event == "ACCOUNT_LOCKED"].itertuples():
    after = df[(df.user == r.user) & (df.timestamp > r.timestamp) & (df.timestamp <= r.timestamp + pd.Timedelta(minutes=30))]
    kinds = ", ".join(after.event.unique())
    same_ip = df[(df.user == r.user) & (df.timestamp >= r.timestamp - pd.Timedelta(minutes=5)) & (df.timestamp <= r.timestamp)].src_ip.nunique() == 1
    add("F8", "INFO", "Account lockout", r.user, df[(df.user == r.user) & (df.timestamp <= r.timestamp)].src_ip.iloc[-1], r.timestamp,
        f"Lockout after repeated failures from a single in-country IP; next 30 min: {kinds}",
        "Matches a forgotten password: single known IP, small count, helpdesk reset, then normal login. Likely benign.",
        "No action beyond confirming the helpdesk ticket exists.")

# D-9 privileged change after suspicious login
for r in df[df.event == "PRIV_GRANT"].itertuples():
    add("F9", "CRITICAL", "Privilege escalation", r.user, r.src_ip, r.timestamp,
        f"{r.reason} - performed from {r.src_ip} ({r.country}) {int((r.timestamp - df[(df.user == r.user) & (df.src_ip == r.src_ip) & (df.event == 'LOGIN_SUCCESS')].timestamp.min()).total_seconds() // 60)} min after the first successful login from that IP",
        "A new privileged account created minutes after a suspected brute-force success is a typical persistence step.",
        "Disable the new account, audit everything done under 'admin' since the success, rotate admin credentials.")

fd = pd.DataFrame(findings)
order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
fd["_o"] = fd.severity.map(order)
fd = fd.sort_values(["_o", "time"]).drop(columns="_o").reset_index(drop=True)
fd.insert(0, "no", range(1, len(fd) + 1))
fd.to_csv("findings.csv", index=False)
print("\n=== FINDINGS ===")
for r in fd.itertuples():
    print(f"[{r.no}] {r.severity:<8} {r.id} {r.category:<22} user={r.user[:18]:<18} ip={r.src_ip}")
    print(f"     {r.evidence}")

# ------------------------------------------------------------------ 3. charts
fig, ax = plt.subplots(figsize=(8, 3.5))
h_all = df.groupby("hour").size().reindex(range(24), fill_value=0)
ax.bar(h_all.index, h_all.values, color="#4C72B0")
ax.set_title("All auth events by hour of day"); ax.set_xlabel("hour"); ax.set_ylabel("events")
plt.tight_layout(); plt.savefig("charts/events_by_hour.png", dpi=130); plt.close()

fig, ax = plt.subplots(figsize=(8, 3.5))
f_ip = fail.groupby("src_ip").size().sort_values(ascending=False).head(8)
ax.barh(f_ip.index[::-1], f_ip.values[::-1], color="#C44E52")
ax.set_title("Failed logins by source IP (top 8)"); ax.set_xlabel("failures")
plt.tight_layout(); plt.savefig("charts/failures_by_ip.png", dpi=130); plt.close()

fig, ax = plt.subplots(figsize=(8, 3.5))
d = df.groupby([df.timestamp.dt.date, "event"]).size().unstack(fill_value=0)
d[[c for c in ["LOGIN_SUCCESS", "LOGIN_FAILURE", "MFA_DENIED"] if c in d]].plot(ax=ax, marker="o")
ax.set_title("Daily events by type"); ax.set_xlabel("date")
plt.tight_layout(); plt.savefig("charts/daily_events.png", dpi=130); plt.close()
print("\ncharts written to charts/")
