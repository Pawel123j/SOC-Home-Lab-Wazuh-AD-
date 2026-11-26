"""A doc citing a custom rule id that is not in the XML must fail the docs check.

Custom ids span 100000..120000 (CUSTOM_ID_MIN..CUSTOM_ID_MAX in
validate_detections.py). Runs scripts/validate_docs_against_rules.py through its
CLI on an isolated copy of the script, rules XML and docs/ in tmp_path.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
DOC = "docs/detections/persistence-scheduled-task.md"
INPUTS = ["scripts/validate_docs_against_rules.py", "detection-rules/custom-wazuh-rules.xml", "docs"]


def run_with_line(tmp_path, line=None):
    for item in INPUTS:
        source, target = ROOT / item, tmp_path / item
        target.parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if source.is_dir() else shutil.copy)(source, target)
    if line:
        with (tmp_path / DOC).open("a", encoding="utf-8") as doc:
            doc.write(f"\n{line}\n")
    result = subprocess.run(
        [sys.executable, str(tmp_path / INPUTS[0])], capture_output=True, text=True, timeout=60,
    )
    return result.returncode, result.stdout + result.stderr


def test_existing_citations_pass(tmp_path):
    code, output = run_with_line(tmp_path, "Powiązana reguła: `100241`.")
    assert code == 0, output


@pytest.mark.parametrize("rule_id", ["100000", "100999", "110001", "119999", "120000"])
def test_missing_custom_rule_citation_fails(tmp_path, rule_id):
    code, output = run_with_line(tmp_path, f"Zobacz też regułę `{rule_id}`.")
    assert code == 1, output
    assert f"{DOC}: cytuje nieistniejącą regułę {rule_id}" in output


@pytest.mark.parametrize("line", [
    "Wbudowane reguły `5710`, `60122` i `91802`.",   # Wazuh built-ins, not custom ids
    "Reguła `099999` i `120001` są poza zakresem.",   # just outside 100000..120000
    "Okno 120 s, port 1024, 8 prób.",
])
def test_numbers_outside_custom_range_are_not_citations(tmp_path, line):
    code, output = run_with_line(tmp_path, line)
    assert code == 0, output
