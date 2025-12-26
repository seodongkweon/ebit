"""
Behavioral tests for SSH brute-force attack detection.

These tests validate:
- 10-minute sliding window logic
- Earliest qualifying window per IP
- Correct first/last attempt timestamps
- Ignoring invalid lines
- Anti-cheating (empty output is not allowed)
"""

import json
import subprocess
from pathlib import Path
from textwrap import dedent

INPUT = Path("/data/auth.log")
OUTPUT = Path("/output/ssh_bruteforce_attacks.json")
APP = "/solution/solve.sh"


def write_log(content: str):
    INPUT.parent.mkdir(parents=True, exist_ok=True)
    INPUT.write_text(content)


def run_detector():
    """
    Runs the brute-force detection program.
    Must generate /output/ssh_bruteforce_attacks.json
    """
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["sh", APP], check=True)

def load_output():
    assert OUTPUT.exists(), "Output file was not created"
    return json.loads(OUTPUT.read_text())


def test_detects_bruteforce_within_10_min_window():
    """
    Detects 5 failed attempts from the same IP within 10 minutes.
    """
    write_log(dedent("""\
        Jan 10 12:00:01 server sshd[1]: Failed password for root from 1.2.3.4
        Jan 10 12:01:10 server sshd[1]: Failed password for root from 1.2.3.4
        Jan 10 12:03:20 server sshd[1]: Failed password for root from 1.2.3.4
        Jan 10 12:06:00 server sshd[1]: Failed password for root from 1.2.3.4
        Jan 10 12:09:30 server sshd[1]: Failed password for root from 1.2.3.4
    """))

    run_detector()
    data = load_output()

    assert len(data) == 1
    e = data[0]
    assert e["source_ip"] == "1.2.3.4"
    assert e["attempt_count"] == 5
    assert e["first_attempt"] == "Jan 10 12:00:01"
    assert e["last_attempt"] == "Jan 10 12:09:30"


def test_does_not_count_outside_window():
    """
    Failed attempts outside the 10-minute window must not be grouped.
    """
    write_log(dedent("""\
        Jan 10 12:00:00 server sshd[1]: Failed password for root from 5.6.7.8
        Jan 10 12:11:01 server sshd[1]: Failed password for root from 5.6.7.8
        Jan 10 12:12:02 server sshd[1]: Failed password for root from 5.6.7.8
        Jan 10 12:13:03 server sshd[1]: Failed password for root from 5.6.7.8
        Jan 10 12:14:04 server sshd[1]: Failed password for root from 5.6.7.8
    """))

    run_detector()
    data = load_output()
    assert data == []


def test_reports_earliest_qualifying_window_only():
    """
    Only the earliest qualifying window per IP is reported.
    """
    write_log(dedent("""\
        Jan 10 12:00:00 server sshd[1]: Failed password for root from 9.9.9.9
        Jan 10 12:01:00 server sshd[1]: Failed password for root from 9.9.9.9
        Jan 10 12:02:00 server sshd[1]: Failed password for root from 9.9.9.9
        Jan 10 12:03:00 server sshd[1]: Failed password for root from 9.9.9.9
        Jan 10 12:04:00 server sshd[1]: Failed password for root from 9.9.9.9

        Jan 10 12:20:00 server sshd[1]: Failed password for root from 9.9.9.9
        Jan 10 12:21:00 server sshd[1]: Failed password for root from 9.9.9.9
        Jan 10 12:22:00 server sshd[1]: Failed password for root from 9.9.9.9
        Jan 10 12:23:00 server sshd[1]: Failed password for root from 9.9.9.9
        Jan 10 12:24:00 server sshd[1]: Failed password for root from 9.9.9.9
    """))

    run_detector()
    data = load_output()

    assert len(data) == 1
    assert data[0]["first_attempt"] == "Jan 10 12:00:00"
    assert data[0]["last_attempt"] == "Jan 10 12:04:00"


def test_ignores_invalid_lines_and_ips():
    """
    Non-failed-password lines and invalid IPs are ignored.
    """
    write_log(dedent("""\
        Jan 10 12:00:00 server sshd[1]: Accepted password for root from 1.1.1.1
        Jan 10 12:01:00 server sshd[1]: Failed password for root
        Jan 10 12:02:00 server sshd[1]: Failed password for root from not_an_ip
    """))

    run_detector()
    data = load_output()
    assert data == []


def test_empty_output_is_not_allowed_when_attack_exists():
    """
    Anti-cheating test: empty output must not pass
    when a brute-force pattern clearly exists.
    """
    write_log(dedent("""\
        Jan 10 12:00:01 server sshd[1]: Failed password for root from 2.2.2.2
        Jan 10 12:01:01 server sshd[1]: Failed password for root from 2.2.2.2
        Jan 10 12:02:01 server sshd[1]: Failed password for root from 2.2.2.2
        Jan 10 12:03:01 server sshd[1]: Failed password for root from 2.2.2.2
        Jan 10 12:04:01 server sshd[1]: Failed password for root from 2.2.2.2
    """))

    run_detector()
    data = load_output()
    assert len(data) == 1
