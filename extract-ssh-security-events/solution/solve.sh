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
  ts = $1 " " $2 " " $3

  if ($0 ~ /Failed password/) {
    match($0, /Failed password for ([^ ]+)/, u)
    match($0, /from ([0-9.]+)/, ip)
    if (u[1] && ip[1]) {
      emit(ts, "FAILED_LOGIN", u[1], ip[1])
    }
  }
  else if ($0 ~ /Invalid user/) {
    match($0, /Invalid user ([^ ]+)/, u)
    match($0, /from ([0-9.]+)/, ip)
    if (u[1] && ip[1]) {
      emit(ts, "INVALID_USER", u[1], ip[1])
    }
  }
  else if ($0 ~ /Accepted password/ && $0 ~ / root /) {
    match($0, /from ([0-9.]+)/, ip)
    if (ip[1]) {
      emit(ts, "ROOT_LOGIN", "root", ip[1])
    }
  }
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
