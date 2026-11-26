"""Run scripts/validate_detections.py on an isolated working copy of the rules.

The validator resolves paths from its own location, so each test copies the
script and the inputs it reads into tmp_path, edits the copied XML and runs the
CLI exactly as CI does. The repository files are never modified.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RULES = "detection-rules/custom-wazuh-rules.xml"
INPUTS = ["scripts/validate_detections.py", "detection-rules", "infrastructure/docker/test-events"]


def run_on_copy(tmp_path, *replacements):
    for item in INPUTS:
        source, target = ROOT / item, tmp_path / item
        target.parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if source.is_dir() else shutil.copy)(source, target)
    rules = tmp_path / RULES
    text = rules.read_text(encoding="utf-8")
    for old, new in replacements:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    rules.write_text(text, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(tmp_path / "scripts/validate_detections.py")],
        capture_output=True, text=True, timeout=60,
    )
    return result.returncode, result.stdout + result.stderr


def test_unmodified_copy_passes(tmp_path):
    code, output = run_on_copy(tmp_path)
    assert code == 0, output
    assert "18 reguł, 18 unikalnych ID" in output


def test_repeated_rule_id_fails(tmp_path):
    code, output = run_on_copy(tmp_path, ('<rule id="100240"', '<rule id="100241"'))
    assert code == 1
    assert "reguła 100241: zduplikowane id (występuje 2 raz/y)" in output
    assert "18 reguł, 17 unikalnych ID" in output


@pytest.mark.parametrize("alias", ["0100241", "１００２４１"])
def test_numeric_alias_of_existing_id_fails(tmp_path, alias):
    # Same number as 100241, different string. wazuh-analysisd accepts only
    # 1..6 ASCII digits, so the manager would reject this id.
    code, output = run_on_copy(tmp_path, ('<rule id="100240"', f'<rule id="{alias}"'))
    assert code == 1, output
    assert f"reguła {alias}: id musi mieć 1..6 cyfr ASCII" in output
