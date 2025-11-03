"""
Usage (example):
  python gen_log.py -n 1000 -e 1 --start-days 30 --prefix log

-n, --count = number of files to create (default 1000)
-e, --per-file = number of log entries per file (default 1)
--start-days = how many days in the past to start timestamps (default 30)
--prefix = filename prefix (default 'log')

"""

import os
import json
import time
import argparse
import random
import secrets
import base64
from datetime import datetime, timedelta

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Sample pools for randomized fields
LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
ROLES = ["devops", "admin", "analyst", "auditor", "user"]
TEAMS = ["infra-team", "storage-team", "app-team", "sec-team"]
ACTION_TYPES = ["deploy", "read", "write", "delete", "config_change"]
RESOURCE_TYPES = ["VM", "Container", "Bucket", "Database"]
SERVICES = ["EC2", "S3", "RDS", "K8S"]
REGIONS = ["us-east-1", "us-west-2", "eu-central-1", "ap-southeast-1"]
APPLICATIONS = ["deployment-agent", "ingest-agent", "audit-collector", "auth-service"]
SAMPLE_MESSAGES = [
    "Deployed container update to production cluster",
    "Configuration applied",
    "User accessed resource",
    "Privilege escalation detected",
    "Integrity check passed",
]

def make_encrypted_placeholder(byte_len=256):
    """Return a base64-encoded random bytes blob to simulate encrypted payload."""
    return base64.b64encode(secrets.token_bytes(byte_len)).decode("ascii")

def random_ip():
    # generate a private IPv4 address in 10.x.x.x or 172.16.x.x range
    if random.random() < 0.5:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"172.16.{random.randint(0,255)}.{random.randint(1,254)}"

def make_log_entry(index, timestamp):
    """Create a single log entry dict resembling the user's example with some randomization."""
    user_id = f"u-{secrets.token_hex(3)}"
    role = random.choice(ROLES)
    team = random.choice(TEAMS)
    action = random.choice(ACTION_TYPES)
    resource_id = f"res-{secrets.token_hex(4)}"
    resource_type = random.choice(RESOURCE_TYPES)
    service = random.choice(SERVICES)
    region = random.choice(REGIONS)
    instance_id = f"pod-{secrets.token_hex(5)}"

    # A simple ABE policy string using role and team to simulate PQ-ABE policy
    abe_policy = f"(role:{role} AND team:{team})"

    entry = {
        "timestamp": timestamp.isoformat() + "Z",
        "user_id": user_id,
        "user_role": role,
        "team": team,
        "action_type": action,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "resource_owner": f"project-{random.choice(['alpha','beta','gamma'])}",
        "service_name": service,
        "region": region,
        "instance_id": instance_id,
        "ip_address": random_ip(),
        "abe_policy": abe_policy,
        "application": random.choice(APPLICATIONS),
        "event_description": random.choice(SAMPLE_MESSAGES),
        "encrypted_payload": make_encrypted_placeholder(128),
    }
    return entry

def generate_logs(count=1000, per_file=1, start_days=30, prefix="log"):
    """Generate `count` files under LOG_DIR.

    - `per_file` entries will be written into each file (as a list). If 1, each file
      contains a single JSON object.
    - Timestamps progress from now - start_days up to now (linearly across all entries).
    """
    total_entries = max(1, count * max(1, per_file))
    now = datetime.utcnow()
    start_dt = now - timedelta(days=float(start_days))
    created = []

    # Precompute timestamps linearly spaced from start_dt to now
    timestamps = []
    if total_entries == 1:
        timestamps = [now]
    else:
        for i in range(total_entries):
            frac = i / (total_entries - 1)
            ts = start_dt + frac * (now - start_dt)
            timestamps.append(ts)

    zero = len(str(count))
    entry_idx = 0
    for i in range(1, count + 1):
        filename = f"{prefix}{str(i).zfill(zero)}.json"
        path = os.path.join(LOG_DIR, filename)
        if per_file == 1:
            entry = make_log_entry(entry_idx + 1, timestamps[entry_idx])
            with open(path, "w", encoding="utf-8") as f:
                json.dump(entry, f, ensure_ascii=False, indent=2)
            entry_idx += 1
        else:
            entries = []
            for _ in range(per_file):
                entries.append(make_log_entry(entry_idx + 1, timestamps[entry_idx]))
                entry_idx += 1
            with open(path, "w", encoding="utf-8") as f:
                json.dump(entries, f, ensure_ascii=False, indent=2)
        created.append(path)

    return created

def parse_args():
    p = argparse.ArgumentParser(description="Generate simulated JSON log files (PQ-ABE simulated payloads).")
    p.add_argument("--count", "-n", type=int, default=1000, help="Number of log files to create (default 1000)")
    p.add_argument("--per-file", "-e", type=int, default=1, help="Number of log entries per file (default 1)")
    p.add_argument("--start-days", "-s", type=float, default=30.0, help="How many days in the past to start timestamps (default 30)")
    p.add_argument("--prefix", type=str, default="log", help="Filename prefix (default 'log')")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    t0 = time.time()
    created = generate_logs(count=args.count, per_file=args.per_file, start_days=args.start_days, prefix=args.prefix)
    t1 = time.time()
    print(f"Generated {len(created)} log files in '{LOG_DIR}' (elapsed {t1 - t0:.2f}s)")
    if created:
        print("Example:", created[0], "...", created[-1])