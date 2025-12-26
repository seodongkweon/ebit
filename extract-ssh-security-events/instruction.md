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

2. Invalid user login attempts  
   - Log line contains the phrase: "Invalid user"

3. Successful SSH login by the root user  
   - Log line contains both:
     - "Accepted password"
     - "root"

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

---

## Parsing Rules

- The timestamp must be extracted exactly as it appears at the beginning of the log line  
  (e.g. "Jan 10 12:03:21")

- The username must be extracted from the log line:
  - For failed logins: the username after "Failed password for"
  - For invalid users: the username after "Invalid user"
  - For root login: always "root"

- The source_ip must be extracted from the IP address following the word "from"

---

## Constraints

- Do not include duplicate events.
  - Two events are considered duplicates if all four fields are identical.

- Preserve the original order of appearance in the log file.

- Ignore non-SSH-related log entries.

- Do not perform any network calls.

- Do not modify the input file.

---

## Edge Cases

- Lines with missing IP addresses must be ignored.
- Lines that partially match the phrases but do not meet all conditions must be ignored.
- Log lines may contain additional text after the IP address.

---

## Notes

- The solution must be deterministic.
- The output file must always be generated, even if no events are found.
- If no events are found, output an empty JSON array.

---

## Success Criteria

The task is considered complete if the output file
`/output/ssh_security_events.json` is generated and contains
exactly the security-relevant SSH events defined above,
with correct parsing, ordering, and no duplicates.
