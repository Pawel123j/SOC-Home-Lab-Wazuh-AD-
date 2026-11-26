"""A missing docker or wazuh-logtest binary is an error, never a skip or a result.

Runs scripts/run_wazuh_fixtures.py through its CLI. The "working" control uses
a local fake `docker` that evaluates only the rules' <field> PCRE2 patterns;
none of these fakes is Wazuh.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/run_wazuh_fixtures.py"
sys.path.insert(0, str(ROOT / "scripts"))
from run_wazuh_fixtures import CASES  # noqa: E402

MISSING_LOGTEST = """#!/bin/sh
cat >/dev/null
echo 'OCI runtime exec failed: exec: "/var/ossec/bin/wazuh-logtest": stat /var/ossec/bin/wazuh-logtest: no such file or directory: unknown' >&2
exit 127
"""

WORKING_LOGTEST = f"""#!{sys.executable}
import json, sys
import pcre2
from xml.etree import ElementTree
sys.path.insert(0, {str(ROOT / "scripts")!r})
from run_wazuh_fixtures import CASES, ROOT
rules = {{r.get("id"): r for r in
         ElementTree.parse(ROOT / "detection-rules/custom-wazuh-rules.xml").getroot().iter("rule")}}
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
"""


def run_cli(tmp_path, fake=None):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    path = str(bin_dir)
    if fake is not None:
        (bin_dir / "docker").write_text(fake)
        (bin_dir / "docker").chmod(0o755)
        path += os.pathsep + os.environ["PATH"]
    report = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--container", "isolated-test", "--output", str(report)],
        capture_output=True, text=True, timeout=120, env=dict(os.environ, PATH=path),
    )
    return result.returncode, result.stdout + result.stderr, report


def test_working_logtest_produces_report(tmp_path):
    code, output, report = run_cli(tmp_path, WORKING_LOGTEST)
    assert code == 0, output
    data = json.loads(report.read_text())
    assert (data["false_negatives"], data["false_positives"], len(data["records"])) == (0, 0, 2 * len(CASES))


def test_missing_docker_binary_fails_without_report(tmp_path):
    code, output, report = run_cli(tmp_path, fake=None)
    assert code != 0
    assert "No such file or directory: 'docker'" in output
    assert not report.exists()
    assert "FN=" not in output


def test_missing_logtest_in_container_fails_without_report(tmp_path):
    code, output, report = run_cli(tmp_path, MISSING_LOGTEST)
    assert code == 1
    assert "logtest failed (127)" in output
    assert not report.exists()
    assert "FN=" not in output
