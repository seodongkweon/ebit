#!/bin/bash
set -euo pipefail

INPUT="/data/auth.log"
OUTPUT="/output/ssh_security_events.json"

mkdir -p /output

echo "[]" > "$OUTPUT"

if [ ! -f "$INPUT" ]; then
  exit 0
fi

TMP="$(mktemp)"

awk '
BEGIN {
  print "["
  first = 1
}
{
  # Skip non-SSH related entries
  if ($0 !~ /ssh/ && $0 !~ /sshd/) next
  
  ts = $1 " " $2 " " $3

  # Failed password for non-root users
  if ($0 ~ /Failed password/ && $0 !~ /Failed password for root/) {
    match($0, /Failed password for ([^ ]+)/, u)
    match($0, /from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/, ip)
    if (u[1] && ip[1] && validate_ip(ip[1])) {
      emit(ts, "FAILED_LOGIN", u[1], ip[1])
    }
  }
  # Failed password for root
  else if ($0 ~ /Failed password for root/) {
    match($0, /from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/, ip)
    if (ip[1] && validate_ip(ip[1])) {
      emit(ts, "ROOT_FAILED", "root", ip[1])
    }
  }
  # Invalid user (SSH only)
  else if ($0 ~ /Invalid user/) {
    match($0, /Invalid user ([^ ]+)/, u)
    match($0, /from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/, ip)
    if (u[1] && ip[1] && validate_ip(ip[1])) {
      emit(ts, "INVALID_USER", u[1], ip[1])
    }
  }
  # Successful root login via SSH
  else if ($0 ~ /Accepted password/ && $0 ~ / root / && $0 ~ /ssh/) {
    match($0, /from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/, ip)
    if (ip[1] && validate_ip(ip[1])) {
      emit(ts, "ROOT_LOGIN", "root", ip[1])
    }
  }
  # Suspicious connections
  else if ($0 ~ /Connection from/) {
    match($0, /Connection from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/, ip)
    if (ip[1] && validate_ip(ip[1]) && is_suspicious_ip(ip[1])) {
      # Store for potential suspicious connection event
      suspicious_ips[ip[1]] = ts
    }
  }
  
  # Check for failed auth after suspicious connection
  if ($0 ~ /authentication failure/ || $0 ~ /Failed password/) {
    match($0, /from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/, ip)
    if (ip[1] && ip[1] in suspicious_ips) {
      emit(suspicious_ips[ip[1]], "SUSPICIOUS_CONNECTION", "unknown", ip[1])
      delete suspicious_ips[ip[1]]
    }
  }
}

function validate_ip(ip) {
  split(ip, octets, ".")
  if (length(octets) != 4) return 0
  for (i in octets) {
    if (octets[i] < 0 || octets[i] > 255) return 0
  }
  return 1
}

function is_suspicious_ip(ip) {
  # Check for private network ranges
  if (ip ~ /^192\.168\./) return 1
  if (ip ~ /^10\./) return 1
  
  # Check for 4+ consecutive identical digits
  for (digit = 0; digit <= 9; digit++) {
    pattern = digit digit digit digit
    if (index(ip, pattern) > 0) return 1
  }
  
  return 0
}

function emit(ts, type, user, ip, key) {
  key = ts "|" type "|" user "|" ip
  if (!seen[key]++) {
    if (!first) print ","
    first = 0
    printf "  {\"timestamp\":\"%s\",\"event_type\":\"%s\",\"username\":\"%s\",\"source_ip\":\"%s\"}", ts, type, user, ip
  }
}
END {
  print "\n]"
}
' "$INPUT" > "$TMP" || true

if [ -s "$TMP" ]; then
  mv "$TMP" "$OUTPUT"
else
  rm -f "$TMP"
fi
