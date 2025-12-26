# Extract SSH Security Events from System Logs

You are given a Linux authentication log file that contains various SSH-related events.

Your task is to extract **security-relevant SSH events**, normalize them, and write the results to a JSON file.

---

## Input File

The input log file is located at:

/data/auth.log

---

## SSH Security Events Definition

An event is considered a **security-relevant SSH event** if **any** of the following conditions are met:

1. Failed SSH login attempts  
   - Log line contains the phrase: "Failed password"
   - Must have both username and source IP
   - Username must NOT be "root" (root failures are handled separately)

2. Invalid user login attempts  
   - Log line contains the phrase: "Invalid user"
   - Must have both username and source IP
   - Only count if the attempt was made via SSH (line contains "ssh" or "sshd")

3. Successful SSH login by the root user  
   - Log line contains both "Accepted password" AND "root"
   - Must have source IP
   - Only count if connection method is "ssh" (not "console" or other methods)

4. Failed root login attempts
   - Log line contains "Failed password for root"
   - Must have source IP
   - Must be via SSH connection

5. SSH connection attempts from suspicious patterns
   - Log line contains "Connection from" 
   - Source IP must match suspicious pattern: starts with "192.168." OR "10." OR contains more than 3 consecutive identical digits
   - Must be followed by a failed authentication within the same minute

---

## Output File

Write the extracted results to:

/output/ssh_security_events.json

---

## Output Format

The output must be a JSON array.

Each element must be an object with the following keys:

- timestamp (string)
- event_type (string)
- username (string)
- source_ip (string)

### event_type Values

Use **only** the following values:

- "FAILED_LOGIN"
- "INVALID_USER"  
- "ROOT_LOGIN"
- "ROOT_FAILED"
- "SUSPICIOUS_CONNECTION"

---

## Parsing Rules

- The timestamp must be extracted exactly as it appears at the beginning of the log line  
  (e.g. "Jan 10 12:03:21")

- The username must be extracted from the log line:
  - For failed logins: the username after "Failed password for" (excluding root)
  - For invalid users: the username after "Invalid user"
  - For root login: always "root"
  - For root failed: always "root"
  - For suspicious connections: extract from subsequent failed auth line, or "unknown" if not found

- The source_ip must be extracted from the IP address following the word "from"

- For suspicious connections, the IP must be validated against the pattern rules

---

## Constraints

- Do not include duplicate events.
  - Two events are considered duplicates if all four fields are identical.

- Preserve the original order of appearance in the log file.

- Ignore non-SSH-related log entries (must contain "ssh" or "sshd" in the log line).

- Lines without valid IP addresses (format: X.X.X.X where X is 1-3 digits) must be ignored.

- For suspicious connections, only include if there's a corresponding failed auth within 60 seconds.

- Do not perform any network calls.

- Do not modify the input file.

---

## Edge Cases

- Lines with missing IP addresses must be ignored.
- Lines that partially match the phrases but do not meet all conditions must be ignored.
- Log lines may contain additional text after the IP address.
- Timestamps may have different formats - handle "MMM dd HH:mm:ss" format only.
- Multiple events from the same IP within the same second should be treated as separate events if usernames differ.
- Connection attempts without subsequent authentication should be ignored.

---

## Notes

- The solution must be deterministic.
- The output file must always be generated, even if no events are found.
- If no events are found, output an empty JSON array.
- Pay careful attention to the suspicious connection pattern matching.
- Root login attempts (both successful and failed) are treated as separate event types.

---

## Success Criteria

The task is considered complete if the output file
`/output/ssh_security_events.json` is generated and contains
exactly the security-relevant SSH events defined above,
with correct parsing, ordering, pattern matching, and no duplicates.
