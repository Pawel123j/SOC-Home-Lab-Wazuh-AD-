"""Rule snippets quoted in docs/ must be the rule that is in the XML.

Runs scripts/validate_docs_against_rules.py through its CLI on an isolated copy
of the script, rules XML and docs/ in tmp_path.
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RULES = "detection-rules/custom-wazuh-rules.xml"
DOC = "docs/detections/persistence-scheduled-task.md"
INPUTS = ["scripts/validate_docs_against_rules.py", RULES, "docs"]
IMAGE_FIELD = '<field name="win.eventdata.image" type="pcre2">(?i)\\\\schtasks\\.exe$</field>'


def run_on_copy(tmp_path, edits=()):
    for item in INPUTS:
        source, target = ROOT / item, tmp_path / item
        target.parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if source.is_dir() else shutil.copy)(source, target)
    for relative, old, new in edits:
        path = tmp_path / relative
        text = path.read_text(encoding="utf-8")
        assert text.count(old) == 1, old
        path.write_text(text.replace(old, new), encoding="utf-8")
    result = subprocess.run([sys.executable, str(tmp_path / INPUTS[0])],
                            capture_output=True, text=True, timeout=60)
    return result.returncode, result.stdout + result.stderr


def test_docs_quote_the_rules_as_they_are(tmp_path):
    code, output = run_on_copy(tmp_path)
    assert code == 0, output


def test_pattern_changed_only_in_docs_fails(tmp_path):
    code, output = run_on_copy(tmp_path, [(DOC, IMAGE_FIELD, IMAGE_FIELD.replace("schtasks", "at"))])
    assert code == 1
    assert f"{DOC}: blok XML reguły 100241 różni się" in output


def test_rule_changed_only_in_xml_fails(tmp_path):
    code, output = run_on_copy(tmp_path, [(RULES, IMAGE_FIELD, IMAGE_FIELD.replace("schtasks", "at"))])
    assert code == 1
    assert "blok XML reguły 100241 różni się" in output


def test_whole_snippet_indentation_and_blank_lines_do_not_matter(tmp_path):
    text = (ROOT / DOC).read_text(encoding="utf-8")
    start = text.index('<rule id="100241"')
    end = text.index("</rule>", start) + len("</rule>")
    rule = text[start:end]
    indented = "\n".join("    " + line for line in rule.replace(IMAGE_FIELD, IMAGE_FIELD + "\n").splitlines())
    code, output = run_on_copy(tmp_path, [(DOC, rule, indented)])
    assert code == 0, output
