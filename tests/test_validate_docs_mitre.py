"""Run scripts/validate_docs_against_rules.py on an isolated copy of rules and docs.

The checker resolves paths from its own location, so each test copies the
script, the rules XML and docs/ into tmp_path, edits the copies and runs the
CLI as CI does. Repository files are never modified.
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RULES = "detection-rules/custom-wazuh-rules.xml"
RESULTS = "docs/04-detection-results.md"
INPUTS = ["scripts/validate_docs_against_rules.py", RULES, "docs"]

# Rule 100212 only: 100299 also lists T1027, so anchor on its <group>.
MITRE_100212 = ("      <id>T1027</id>\n    </mitre>\n"
                "    <group>execution,defense_evasion,powershell,sysmon,ps_c2_indicator,</group>")
COMMENTED_T1105 = MITRE_100212.replace(
    "<id>T1027</id>\n", "<id>T1027</id>\n      <!-- <id>T1105</id> wycofane -->\n", 1)
ROW_100212 = "| T1059.001, T1027 |"


def run_on_copy(tmp_path, rules=(), results=()):
    for item in INPUTS:
        source, target = ROOT / item, tmp_path / item
        target.parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if source.is_dir() else shutil.copy)(source, target)
    for relative, replacements in ((RULES, rules), (RESULTS, results)):
        path = tmp_path / relative
        text = path.read_text(encoding="utf-8")
        for old, new in replacements:
            assert text.count(old) == 1, old
            text = text.replace(old, new)
        path.write_text(text, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(tmp_path / "scripts/validate_docs_against_rules.py")],
        capture_output=True, text=True, timeout=60,
    )
    return result.returncode, result.stdout + result.stderr


def test_unmodified_copy_passes(tmp_path):
    code, output = run_on_copy(tmp_path)
    assert code == 0, output
    assert "zgodnych z 18 regułami" in output


def test_doc_row_missing_a_technique_fails(tmp_path):
    code, output = run_on_copy(tmp_path, results=[(ROW_100212, "| T1059.001 |")])
    assert code == 1
    assert "reguła 100212 ma w dokumencie MITRE ['T1059.001'], a w XML ['T1027', 'T1059.001']" in output


def test_commented_out_technique_is_not_part_of_the_rule(tmp_path):
    code, output = run_on_copy(tmp_path, rules=[(MITRE_100212, COMMENTED_T1105)])
    assert code == 0, output


def test_doc_citing_commented_out_technique_fails(tmp_path):
    code, output = run_on_copy(
        tmp_path,
        rules=[(MITRE_100212, COMMENTED_T1105)],
        results=[(ROW_100212, "| T1059.001, T1027, T1105 |")],
    )
    assert code == 1
    assert ("reguła 100212 ma w dokumencie MITRE ['T1027', 'T1059.001', 'T1105'], "
            "a w XML ['T1027', 'T1059.001']") in output


def test_malformed_xml_is_reported_not_crashed(tmp_path):
    code, output = run_on_copy(tmp_path, rules=[(MITRE_100212, MITRE_100212 + "<")])
    assert code == 1
    assert "Nie udało się sparsować żadnej reguły" in output
