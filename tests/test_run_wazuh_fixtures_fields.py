"""Required fields of a ready fixture, checked through the run_wazuh_fixtures.py CLI.

A negative sample replaces win.eventdata.<field>. If the fixture has no such
field, there is no negative to test: the runner must stop before calling the
manager instead of scoring the rule. `docker` is a local fake that evaluates
only the <field> PCRE2 patterns of the rules in CASES; it is not Wazuh.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
EVENTS = "infrastructure/docker/test-events"
INPUTS = ["scripts/run_wazuh_fixtures.py", "detection-rules/custom-wazuh-rules.xml", EVENTS]

FAKE_DOCKER = '''
import json, os, pathlib, sys
import pcre2
from xml.etree import ElementTree
copy = pathlib.Path(os.environ["FAKE_COPY"])
with (copy / "docker-calls.log").open("a") as log:
    log.write("call\\n")
sys.path.insert(0, str(copy / "scripts"))
from run_wazuh_fixtures import CASES
rules = {r.get("id"): r for r in
         ElementTree.parse(copy / "detection-rules/custom-wazuh-rules.xml").getroot().iter("rule")}
event = json.loads(sys.stdin.read())

def hit(rule_id):
    for field in rules[rule_id].findall("field"):
        value = event
        for part in field.get("name").split("."):
            if not isinstance(value, dict) or part not in value:
                return False
            value = value[part]
        if pcre2.search(field.text, str(value)) is None:
            return False
    return True

ids = [rule_id for _, rule_id, *_ in CASES if hit(rule_id)]
print("**Phase 3: Completed filtering (rules).\\n\\tid: '%s'" % (ids[0] if ids else "61603"))
'''


def run_cli(tmp_path, edit_fixture=None, edit_script=None):
    for item in INPUTS:
        source, target = ROOT / item, tmp_path / item
        target.parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if source.is_dir() else shutil.copy)(source, target)
    if edit_fixture:
        name, old, new = edit_fixture
        path = tmp_path / EVENTS / name
        event = json.loads(path.read_text())
        event["win"]["eventdata"][new] = event["win"]["eventdata"].pop(old)
        path.write_text(json.dumps(event, indent=2))
    if edit_script:
        old, new = edit_script
        path = tmp_path / INPUTS[0]
        text = path.read_text()
        assert text.count(old) == 1, old
        path.write_text(text.replace(old, new))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(f"#!{sys.executable}\n{FAKE_DOCKER}")
    (bin_dir / "docker").chmod(0o755)
    report = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, str(tmp_path / INPUTS[0]), "--container", "fake", "--output", str(report)],
        capture_output=True, text=True, timeout=120,
        env=dict(os.environ, FAKE_COPY=str(tmp_path),
                 PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}"),
    )
    calls = tmp_path / "docker-calls.log"
    return (result.returncode, result.stdout + result.stderr,
            json.loads(report.read_text()) if report.exists() else None,
            len(calls.read_text().splitlines()) if calls.exists() else 0)


def test_complete_fixtures_are_scored(tmp_path):
    code, output, report, calls = run_cli(tmp_path)
    assert code == 0, output
    assert (report["false_negatives"], report["false_positives"], calls) == (0, 0, 20)


def test_fixture_without_negative_field_stops_before_manager(tmp_path):
    # Mis-cased key: the rule reads win.eventdata.commandLine.
    code, output, report, calls = run_cli(
        tmp_path, edit_fixture=("04-ps-encoded.json", "commandLine", "CommandLine"))
    assert code == 1
    assert "04-ps-encoded.json: no win.eventdata.commandLine" in output
    assert (report, calls) == (None, 0)


def test_case_naming_absent_field_stops_before_manager(tmp_path):
    # Without the guard this was scored as a false positive of rule 100212.
    code, output, report, calls = run_cli(tmp_path, edit_script=(
        '("04-ps-encoded.json", "100212", "commandLine"',
        '("04-ps-encoded.json", "100212", "CommandLine"'))
    assert code == 1
    assert "04-ps-encoded.json: no win.eventdata.CommandLine" in output
    assert (report, calls) == (None, 0)
