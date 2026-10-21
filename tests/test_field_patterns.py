"""Execute field patterns with PCRE2 on decoded Windows paths.

These tests do not emulate Wazuh's decoders, rule ancestry or correlation state.
The real manager/AD integration remains a separate requirement.
"""

import copy
import json
from pathlib import Path
from xml.etree import ElementTree

import pcre2
import pytest

ROOT = Path(__file__).parents[1]
RULES = {rule.attrib["id"]: rule for rule in
         ElementTree.parse(ROOT / "detection-rules/custom-wazuh-rules.xml").getroot()}
CASES = [
    ("02-lsass-access.json", "100210", "targetImage", r"C:\Windows\System32\notepad.exe"),
    ("03-lsass-comsvcs.json", "100211", "commandLine", "rundll32.exe shell32.dll,Control_RunDLL"),
    ("04-ps-encoded.json", "100212", "commandLine", "powershell.exe -NoProfile Get-Date"),
    ("05-ps-network.json", "100213", "destinationIp", "127.0.0.1"),
    ("06-ps-iex-download.json", "100214", "scriptBlockText", "Write-Output 'hello'"),
    ("07-mshta-remote.json", "100220", "commandLine", r"mshta.exe C:\local.hta"),
    ("08-mshta-child.json", "100221", "parentImage", r"C:\Windows\explorer.exe"),
    ("09-archive-temp.json", "100232", "targetFilename", r"C:\Users\Public\note.txt"),
    ("10-registry-run.json", "100240", "targetObject", r"HKLM\Software\Example\Setting"),
    ("11-scheduled-task.json", "100241", "commandLine", "schtasks.exe /query"),
]


def normalize_paths(value):
    if isinstance(value, dict):
        return {key: normalize_paths(item) for key, item in value.items()}
    if isinstance(value, str):
        return value.replace("\\\\", "\\")
    return value


def matches(rule_id, event):
    for field in RULES[rule_id].findall("field"):
        value = event
        for part in field.attrib["name"].split("."):
            value = value[part]
        if pcre2.search(field.text, str(value)) is None:
            return False
    return True


@pytest.mark.parametrize("filename,rule_id,field,benign", CASES)
def test_realistic_windows_path_and_benign_control(filename, rule_id, field, benign):
    event = normalize_paths(json.loads((ROOT / "infrastructure/docker/test-events" / filename).read_text()))
    assert matches(rule_id, event), f"{rule_id} misses a decoded Windows event"
    negative = copy.deepcopy(event)
    negative["win"]["eventdata"][field] = benign
    assert not matches(rule_id, negative)


def test_lsass_access_mask_requires_complete_value():
    event = normalize_paths(json.loads(
        (ROOT / "infrastructure/docker/test-events/02-lsass-access.json").read_text()
    ))
    event["win"]["eventdata"]["grantedAccess"] = "0x1410ff"
    assert not matches("100210", event)


def test_short_powershell_encoded_command_flag():
    event = normalize_paths(json.loads(
        (ROOT / "infrastructure/docker/test-events/04-ps-encoded.json").read_text()
    ))
    event["win"]["eventdata"]["commandLine"] = "powershell.exe -e " + "A" * 220
    assert matches("100212", event)


def test_fixtures_contain_decoded_single_path_separators():
    for filename, *_ in CASES:
        event = json.loads((ROOT / "infrastructure/docker/test-events" / filename).read_text())
        assert event == normalize_paths(event), filename
