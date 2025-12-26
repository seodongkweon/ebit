import json
from pathlib import Path

OUTPUT = Path("/output/ssh_security_events.json")

def test_valid_json():
    """Test that output is valid JSON array"""
    data = json.loads(OUTPUT.read_text())
    assert isinstance(data, list)

def test_output_file_exists():
    """Test that output file is created"""
    assert OUTPUT.exists(), "Output file was not created"

def test_event_schema():
    """Test that all events have required schema fields"""
    data = json.loads(OUTPUT.read_text())
    for event in data:
        assert set(event.keys()) == {
            "timestamp",
            "event_type", 
            "username",
            "source_ip"
        }

def test_event_type_values():
    """Test that event_type values are from allowed set"""
    data = json.loads(OUTPUT.read_text())
    allowed = {"FAILED_LOGIN", "INVALID_USER", "ROOT_LOGIN", "ROOT_FAILED", "SUSPICIOUS_CONNECTION"}
    for event in data:
        assert event["event_type"] in allowed

def test_no_duplicates():
    """Test that there are no duplicate events"""
    data = json.loads(OUTPUT.read_text())
    seen = set()
    for event in data:
        key = tuple(event.items())
        assert key not in seen
        seen.add(key)

def test_ip_address_format():
    """Test that all source_ip values are valid IP addresses"""
    import re
    data = json.loads(OUTPUT.read_text())
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    for event in data:
        assert ip_pattern.match(event["source_ip"]), f"Invalid IP format: {event['source_ip']}"
        # Validate IP octets are in valid range
        octets = event["source_ip"].split('.')
        for octet in octets:
            assert 0 <= int(octet) <= 255, f"Invalid IP octet: {octet}"

def test_timestamp_format():
    """Test that timestamps follow expected format"""
    import re
    data = json.loads(OUTPUT.read_text())
    # Expected format: "Jan 10 12:03:21"
    ts_pattern = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$')
    for event in data:
        assert ts_pattern.match(event["timestamp"]), f"Invalid timestamp format: {event['timestamp']}"

def test_root_events_separation():
    """Test that root events are properly categorized"""
    data = json.loads(OUTPUT.read_text())
    for event in data:
        if event["username"] == "root":
            assert event["event_type"] in ["ROOT_LOGIN", "ROOT_FAILED"], \
                f"Root user should only have ROOT_LOGIN or ROOT_FAILED events, got: {event['event_type']}"
        elif event["event_type"] == "FAILED_LOGIN":
            assert event["username"] != "root", \
                "FAILED_LOGIN events should not have root username"

def test_suspicious_connection_pattern():
    """Test that suspicious connections match required IP patterns"""
    data = json.loads(OUTPUT.read_text())
    for event in data:
        if event["event_type"] == "SUSPICIOUS_CONNECTION":
            ip = event["source_ip"]
            # Check if IP matches suspicious patterns
            is_suspicious = (
                ip.startswith("192.168.") or 
                ip.startswith("10.") or
                any(digit * 4 in ip for digit in "0123456789")  # 4+ consecutive identical digits
            )
            assert is_suspicious, f"IP {ip} doesn't match suspicious patterns"

def test_non_empty_usernames():
    """Test that usernames are not empty strings"""
    data = json.loads(OUTPUT.read_text())
    for event in data:
        assert event["username"].strip() != "", "Username cannot be empty"
        assert len(event["username"]) > 0, "Username must have content"
