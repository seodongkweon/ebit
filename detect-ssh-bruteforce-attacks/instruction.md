# Detect SSH Brute-Force Attacks from Authentication Logs

You are given a Linux authentication log file that contains SSH login events.

Your task is to detect **potential SSH brute-force attacks**
based on repeated failed login attempts from the same source IP
within a defined time window.

---

## Input File

The input log file is located at:

/data/auth.log

---

## Definition: Failed SSH Login Attempt

A log line represents a failed SSH login attempt if it contains:

- The phrase: "Failed password"

Lines that do not meet this condition must be ignored.

---

## Brute-Force Attack Detection Policy

A **brute-force attack** is detected when **all** of the following conditions are met:

1. The same source IP address generates **5 or more failed SSH login attempts**
2. All attempts occur within a **10-minute sliding time window**

---

## Time Handling Rules

- Timestamps appear at the beginning of each log line
  (e.g. "Jan 10 12:03:21")
- Assume all log entries belong to the same year.
- You may assume the log file is sorted in chronological order.

---

## Output File

Write the detected brute-force attacks to:

/output/ssh_bruteforce_attacks.json

---

## Output Format

The output must be a JSON array.

Each element must be an object with the following keys:

- source_ip (string)
- first_attempt (string)
- last_attempt (string)
- attempt_count (integer)

---

## Output Rules

- Each source IP must appear **at most once** in the output.
- The first_attempt must be the timestamp of the first failed attempt
  within the window that triggered detection.
- The last_attempt must be the timestamp of the last failed attempt
  within that same window.
- attempt_count must reflect the number of failed attempts
  within the detection window.

---

## Constraints

- Preserve deterministic behavior.
- Do not perform any network calls.
- Do not modify the input log file.
- Do not infer or guess missing timestamps.

---

## Edge Cases

- Failed attempts from the same IP outside the 10-minute window
  must not be counted together.
- If an IP generates multiple qualifying windows,
  report only the **earliest** one.
- Lines with missing or malformed IP addresses must be ignored.

---

## Success Criteria

The task is considered complete if the output file
`/output/ssh_bruteforce_attacks.json` contains exactly the brute-force
attacks defined by the policy above, with correct time windows,
counts, and formatting.
