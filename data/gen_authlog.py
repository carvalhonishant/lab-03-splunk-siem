#!/usr/bin/env python3
"""
Generate a realistic Linux SSH auth log for a Splunk ingestion lab.

The log tells a story:
  - routine background noise (cron, sudo, normal logins)
  - a brute force burst from one external IP against several usernames
  - that same IP finally succeeding on the 'admin' account (the breach)
  - a little normal activity afterwards

Output parses cleanly under Splunk's built-in 'linux_secure' sourcetype.
"""

import random
from datetime import datetime, timedelta

HOST = "webserver01"
OUT = "auth.log"

# Start the log a few hours back so timestamps look recent.
start = datetime(2026, 10, 20, 9, 0, 0)

lines = []
pid = 10000

def ts(dt):
    # Syslog style: "Oct 20 09:00:01"
    return dt.strftime("%b %d %H:%M:%S")

def add(dt, msg):
    global pid
    pid += random.randint(1, 7)
    lines.append(f"{ts(dt)} {HOST} sshd[{pid}]: {msg}")

# Normal internal users and their source IPs
normal_users = [
    ("nishant", "10.0.0.14"),
    ("deploy", "10.0.0.22"),
    ("backup", "10.0.0.31"),
]

# Attacker
attacker_ip = "203.0.113.45"
brute_users = ["root", "oracle", "postgres", "admin", "test",
               "ubuntu", "git", "jenkins", "ftpuser", "mysql"]

t = start

# 1. A few hours of light, normal activity
for _ in range(40):
    t += timedelta(seconds=random.randint(30, 400))
    user, ip = random.choice(normal_users)
    port = random.randint(40000, 60000)
    roll = random.random()
    if roll < 0.7:
        add(t, f"Accepted password for {user} from {ip} port {port} ssh2")
        add(t, f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
    elif roll < 0.85:
        # occasional genuine typo, one failure then success
        add(t, f"Failed password for {user} from {ip} port {port} ssh2")
        t += timedelta(seconds=random.randint(3, 20))
        add(t, f"Accepted password for {user} from {ip} port {port+1} ssh2")
    else:
        add(t, f"Received disconnect from {ip} port {port}:11: disconnected by user")

# 2. The brute force burst, mid morning
t = start + timedelta(hours=2, minutes=13)
burst_start = t
for i in range(120):
    t += timedelta(seconds=random.randint(1, 4))
    user = random.choice(brute_users)
    port = random.randint(30000, 65000)
    if user in ("nishant", "deploy", "backup"):
        add(t, f"Failed password for {user} from {attacker_ip} port {port} ssh2")
    else:
        add(t, f"Failed password for invalid user {user} from {attacker_ip} port {port} ssh2")

# 3. The breach: same IP finally gets in on 'admin'
t += timedelta(seconds=3)
breach_time = t
add(t, f"Accepted password for admin from {attacker_ip} port {random.randint(30000,65000)} ssh2")
add(t, f"pam_unix(sshd:session): session opened for user admin by (uid=0)")
t += timedelta(seconds=8)
add(t, f"subsystem request for sftp by user admin")

# 4. A bit of normal activity afterwards so the breach is not the last line
for _ in range(15):
    t += timedelta(seconds=random.randint(30, 300))
    user, ip = random.choice(normal_users)
    port = random.randint(40000, 60000)
    add(t, f"Accepted password for {user} from {ip} port {port} ssh2")

with open(OUT, "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Wrote {len(lines)} lines to {OUT}")
print(f"Brute force burst began around: {ts(burst_start)} from {attacker_ip}")
print(f"Breach (accepted) at:            {ts(breach_time)} user 'admin'")
