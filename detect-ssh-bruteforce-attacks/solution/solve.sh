#!/bin/sh
set -eu

INPUT="/data/auth.log"
OUTPUT="/output/ssh_bruteforce_attacks.json"

mkdir -p /output

if [ ! -f "$INPUT" ]; then
  echo "[]" > "$OUTPUT"
  exit 0
fi

python3 - <<'PY'
import json
from datetime import datetime, timedelta
import re

INPUT = "/data/auth.log"
OUTPUT = "/output/ssh_bruteforce_attacks.json"

pattern = re.compile(r"^([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}).*Failed password.*from ([0-9.]+)")

def parse_time(ts):
    return datetime.strptime(ts, "%b %d %H:%M:%S")

events = []

with open(INPUT) as f:
    for line in f:
        m = pattern.search(line)
        if not m:
            continue
        ts, ip = m.groups()
        events.append((parse_time(ts), ts, ip))

by_ip = {}
for t, ts, ip in events:
    by_ip.setdefault(ip, []).append((t, ts))

results = []

for ip, attempts in by_ip.items():
    attempts.sort()
    for i in range(len(attempts)):
        window = [attempts[i]]
        for j in range(i + 1, len(attempts)):
            if attempts[j][0] - attempts[i][0] <= timedelta(minutes=10):
                window.append(attempts[j])
            else:
                break
        if len(window) >= 5:
            results.append({
                "source_ip": ip,
                "first_attempt": window[0][1],
                "last_attempt": window[-1][1],
                "attempt_count": len(window),
            })
            break

with open(OUTPUT, "w") as f:
    json.dump(results, f, indent=2)
PY
