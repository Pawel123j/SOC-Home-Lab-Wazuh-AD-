"""Fixtures must carry what the real Windows rule chain needs.

Wazuh derives win.system.severityValue only from Level + Keywords, and base
rules such as 61600 (Sysmon) require it; without both fields no Windows rule
fires on a real manager. Runs scripts/validate_detections.py through its CLI
on an isolated copy in tmp_path.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
EVENTS = "infrastructure/docker/test-events"
INPUTS = ["scripts/validate_detections.py", "detection-rules", EVENTS]


def run_without(tmp_path, key):
    for item in INPUTS:
        source, target = ROOT / item, tmp_path / item
        target.parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if source.is_dir() else shutil.copy)(source, target)
    if key:
        path = tmp_path / EVENTS / "04-ps-encoded.json"
        event = json.loads(path.read_text())
        del event["win"]["system"][key]
        path.write_text(json.dumps(event))
    result = subprocess.run([sys.executable, str(tmp_path / INPUTS[0])],
                            capture_output=True, text=True, timeout=60)
    return result.returncode, result.stdout + result.stderr


def test_fixtures_with_level_and_keywords_pass(tmp_path):
    code, output = run_without(tmp_path, None)
    assert code == 0, output


@pytest.mark.parametrize("key", ["level", "keywords"])
def test_fixture_without_severity_inputs_fails(tmp_path, key):
    code, output = run_without(tmp_path, key)
    assert code == 1
    assert f"04-ps-encoded.json: brak 'win.system.{key}'" in output
