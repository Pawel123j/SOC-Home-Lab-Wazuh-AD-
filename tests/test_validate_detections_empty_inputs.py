"""An empty rule set or fixture directory must never validate as success.

Runs scripts/validate_detections.py through its CLI on an isolated copy of
its inputs in tmp_path; the repository files are never modified.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SIGMA = "detection-rules/sigma-rules"
EVENTS = "infrastructure/docker/test-events"
RULES = "detection-rules/custom-wazuh-rules.xml"
INPUTS = ["scripts/validate_detections.py", "detection-rules", EVENTS]


def run_on_copy(tmp_path, prepare=None):
    for item in INPUTS:
        source, target = ROOT / item, tmp_path / item
        target.parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if source.is_dir() else shutil.copy)(source, target)
    if prepare:
        prepare(tmp_path)
    result = subprocess.run(
        [sys.executable, str(tmp_path / INPUTS[0])], capture_output=True, text=True, timeout=60,
    )
    return result.returncode, result.stdout + result.stderr


def remove(pattern):
    def prepare(base):
        for path in base.glob(pattern):
            path.unlink()
    return prepare


def empty_group(base):
    path = base / RULES
    text = path.read_text(encoding="utf-8")
    path.write_text(text[:text.index("<group name=")] + '<group name="local,">\n</group>\n',
                    encoding="utf-8")


def test_complete_inputs_pass(tmp_path):
    code, output = run_on_copy(tmp_path)
    assert code == 0, output
    sigma = len(list((ROOT / SIGMA).glob("*.yml"))) + len(list((ROOT / SIGMA).glob("*.yaml")))
    events = len(list((ROOT / EVENTS).glob("*.json")))
    assert f"Sigma: {sigma} reguł" in output and f"Zdarzenia: {events} plików JSON" in output


@pytest.mark.parametrize("prepare,message", [
    (remove(f"{SIGMA}/*.yml"), f"{SIGMA}: nie znaleziono żadnej reguły Sigma"),
    (lambda base: shutil.rmtree(base / SIGMA), f"{SIGMA}: nie znaleziono żadnej reguły Sigma"),
    (remove(f"{EVENTS}/*.json"), f"{EVENTS}: nie znaleziono syntetycznych zdarzeń"),
    (empty_group, f"{RULES}: nie znaleziono żadnej reguły"),
], ids=["sigma-only-readme", "sigma-dir-missing", "events-dir-empty", "wazuh-group-without-rules"])
def test_empty_input_fails(tmp_path, prepare, message):
    code, output = run_on_copy(tmp_path, prepare)
    assert code == 1, output
    assert message in output
    assert "OK — wszystkie sprawdzenia przeszły." not in output
