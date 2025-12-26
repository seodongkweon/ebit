import json
from pathlib import Path

OUTPUT = Path("/output/ssh_security_events.json")

def test_valid_json():
    data = json.loads(OUTPUT.read_text())
    assert isinstance(data, list)

def test_output_file_exists():
    assert OUTPUT.exists(), "Output file was not created"

def test_event_schema():
    data = json.loads(OUTPUT.read_text())
    for event in data:
        assert set(event.keys()) == {
            "timestamp",
            "event_type",
            "username",
            "source_ip"
        }

def test_event_type_values():
    data = json.loads(OUTPUT.read_text())
    allowed = {"FAILED_LOGIN", "INVALID_USER", "ROOT_LOGIN"}
    for event in data:
        assert event["event_type"] in allowed

def test_no_duplicates():
    data = json.loads(OUTPUT.read_text())
    seen = set()
    for event in data:
        key = tuple(event.items())
        assert key not in seen
        seen.add(key)
