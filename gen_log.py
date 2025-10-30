"""
Generate a single large log.json file with multiple log entries for LCP-ABE encryption.

Usage:
  python gen_log.py -n 1000 --epoch-duration 30

-n, --count = number of log entries to generate (default 1000)
--epoch-duration = duration of each epoch in minutes (default 30)
--start-hours = how many hours in the past to start timestamps (default 24)

Output: logs/log.json (single file with array of log entries)
"""

import os
import json
import time
import argparse
import random
import secrets
from datetime import datetime, timedelta

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Sample pools for randomized fields
ROLES = ["devops", "admin", "analyst", "auditor", "user"]
TEAMS = ["infra-team", "storage-team", "app-team", "sec-team"]
ACTION_TYPES = ["deploy", "read", "write", "delete", "config_change", "backup", "restore"]
RESOURCE_TYPES = ["VM", "Container", "Bucket", "Database", "Network", "Queue"]
SERVICES = ["EC2", "S3", "RDS", "K8S", "Lambda", "CloudFront"]
REGIONS = ["us-east-1", "us-west-2", "eu-central-1", "ap-southeast-1", "ap-northeast-1"]
APPLICATIONS = ["deployment-agent", "ingest-agent", "audit-collector", "auth-service", "monitoring-daemon"]
SAMPLE_MESSAGES = [
    "Deployed container update to production cluster",
    "Configuration applied successfully",
    "User accessed resource",
    "Privilege escalation detected",
    "Integrity check passed",
    "Database query executed",
    "File upload completed",
    "Service restarted",
]

# Sample log data content (actual commands/queries that get encrypted)
SAMPLE_LOG_DATA = [
    "SELECT * FROM users WHERE id=12345 AND status='active'",
    "kubectl apply -f deployment.yaml --namespace=production",
    "aws s3 cp file.txt s3://bucket/path/",
    "UPDATE config SET value='enabled' WHERE key='feature_flag'",
    "docker pull registry.example.com/app:v1.2.3",
    "INSERT INTO audit_log (user_id, action, timestamp) VALUES (123, 'login', NOW())",
    "terraform apply -auto-approve -var-file=prod.tfvars",
    "git push origin main --force",
    "curl -X POST https://api.example.com/webhook -d '{\"event\":\"deploy\"}'",
    "rm -rf /tmp/cache/*",
]

def random_ip():
    # generate a private IPv4 address in 10.x.x.x or 172.16.x.x range
    if random.random() < 0.5:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"172.16.{random.randint(0,255)}.{random.randint(1,254)}"

def make_log_entry(index, timestamp):
    """Create a single log entry dict matching the LCP-ABE format (no abe_policy, includes log_data)."""
    user_id = f"u-{secrets.token_hex(3)}"
    role = random.choice(ROLES)
    team = random.choice(TEAMS)
    action = random.choice(ACTION_TYPES)
    resource_id = f"res-{secrets.token_hex(4)}"
    resource_type = random.choice(RESOURCE_TYPES)
    service = random.choice(SERVICES)
    region = random.choice(REGIONS)
    instance_id = f"pod-{secrets.token_hex(5)}"

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
        "application": random.choice(APPLICATIONS),
        "event_description": random.choice(SAMPLE_MESSAGES),
        "log_data": random.choice(SAMPLE_LOG_DATA),
    }
    return entry

def generate_logs(count=1000, start_hours=24, epoch_duration=30):
    """Generate a single log.json file with `count` entries.
    
    - Timestamps span from (now - start_hours) to now
    - Distributed to simulate multiple epochs (based on epoch_duration minutes)
    - Output: logs/log.json
    """
    total_entries = max(1, count)
    now = datetime.utcnow()
    start_dt = now - timedelta(hours=float(start_hours))
    
    print(f"Generating {total_entries} log entries...")
    print(f"Time range: {start_dt.isoformat()}Z to {now.isoformat()}Z")
    print(f"Epoch duration: {epoch_duration} minutes")
    
    # Precompute timestamps distributed across the time range
    timestamps = []
    if total_entries == 1:
        timestamps = [now]
    else:
        for i in range(total_entries):
            # Add some randomness within each interval for more realistic distribution
            frac = i / (total_entries - 1)
            base_ts = start_dt + frac * (now - start_dt)
            # Add random offset within ±5 minutes
            offset_minutes = random.uniform(-5, 5)
            ts = base_ts + timedelta(minutes=offset_minutes)
            # Ensure timestamp doesn't go beyond bounds
            ts = max(start_dt, min(now, ts))
            timestamps.append(ts)
    
    # Sort timestamps to ensure chronological order
    timestamps.sort()
    
    # Generate log entries
    entries = []
    for i, ts in enumerate(timestamps):
        entry = make_log_entry(i + 1, ts)
        entries.append(entry)
    
    # Write to single log.json file
    output_path = os.path.join(LOG_DIR, "log.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    
    # Calculate epoch statistics
    epoch_ids = {}
    epoch_seconds = epoch_duration * 60
    for entry in entries:
        ts = datetime.fromisoformat(entry["timestamp"].replace("Z", ""))
        epoch_id = int(ts.timestamp() // epoch_seconds)
        epoch_ids[epoch_id] = epoch_ids.get(epoch_id, 0) + 1
    
    print(f"\nGenerated {len(entries)} log entries")
    print(f"Output: {output_path}")
    print(f"File size: {os.path.getsize(output_path) / 1024:.2f} KB")
    print(f"\nEpoch distribution ({len(epoch_ids)} epochs):")
    for epoch_id in sorted(epoch_ids.keys())[:5]:  # Show first 5 epochs
        print(f"  Epoch {epoch_id}: {epoch_ids[epoch_id]} logs")
    if len(epoch_ids) > 5:
        print(f"  ... and {len(epoch_ids) - 5} more epochs")
    
    return output_path

def parse_args():
    p = argparse.ArgumentParser(
        description="Generate a single log.json file with multiple entries for LCP-ABE encryption testing."
    )
    p.add_argument(
        "--count", "-n", type=int, default=1000,
        help="Number of log entries to generate (default 1000)"
    )
    p.add_argument(
        "--start-hours", type=float, default=24.0,
        help="How many hours in the past to start timestamps (default 24)"
    )
    p.add_argument(
        "--epoch-duration", type=int, default=30,
        help="Epoch duration in minutes for microbatching (default 30)"
    )
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    t0 = time.time()
    
    output_path = generate_logs(
        count=args.count,
        start_hours=args.start_hours,
        epoch_duration=args.epoch_duration
    )
    
    t1 = time.time()
    print(f"\n✓ Complete! (elapsed {t1 - t0:.2f}s)")
    print(f"\nYou can now use '{output_path}' for LCP-ABE encryption testing.")