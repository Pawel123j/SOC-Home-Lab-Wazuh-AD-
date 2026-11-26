"""Exercise scripts/run_wazuh_fixtures.py through its CLI with a fake `docker`.

The fake prints synthetic wazuh-logtest text; it is not Wazuh and proves
nothing about rule matching. It pins how the runner scores negative samples:
an evaluated event that only hits a base rule is "no alarm" (passed), the
excluded rule firing is a false positive, and output with no rule result at
all aborts the run instead of being counted as a pass.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from run_wazuh_fixtures import CASES  # noqa: E402

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
sys.path.insert(0, os.environ["FAKE_REPO"] + "/scripts")
from run_wazuh_fixtures import CASES, ROOT
event = json.loads(sys.stdin.read())
for name, rule_id, *_ in CASES:
    if json.loads((ROOT / "infrastructure/docker/test-events" / name).read_text()) == event:
        print(f"**Phase 3: Completed filtering (rules).\n\tid: '{rule_id}'")
        sys.exit(0)
mode = os.environ["FAKE_NEGATIVE"]
if mode == "base_rule":
    print("**Phase 3: Completed filtering (rules).\n\tid: '61603'")
elif mode == "excluded_rule":
    print("**Phase 3: Completed filtering (rules).\n\tid: '" + os.environ["FAKE_RULE"] + "'")
else:
    print("**Phase 2: Completed decoding.\n\tname: 'windows_eventchannel'")
'''


def run_cli(tmp_path, negative, rule="100212"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "docker"
    fake.write_text(FAKE_DOCKER.replace("#!/usr/bin/env python3", f"#!{sys.executable}", 1))
    fake.chmod(0o755)
    report = tmp_path / "report.json"
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
               FAKE_REPO=str(ROOT), FAKE_NEGATIVE=negative, FAKE_RULE=rule)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/run_wazuh_fixtures.py"),
         "--container", "fake", "--output", str(report)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    data = json.loads(report.read_text()) if report.exists() else None
    return result.returncode, data, result.stdout + result.stderr


def test_negative_with_only_base_rule_is_no_alarm(tmp_path):
    code, report, output = run_cli(tmp_path, "base_rule")
    assert code == 0, output
    assert (report["false_negatives"], report["false_positives"]) == (0, 0)
    negatives = [r for r in report["records"] if r["kind"] == "negative"]
    assert len(negatives) == len(CASES)
    assert {r["actual"] for r in negatives} == {"61603"}


def test_negative_still_hitting_excluded_rule_is_false_positive(tmp_path):
    code, report, _ = run_cli(tmp_path, "excluded_rule", rule="100212")
    assert code == 1
    assert report["false_positives"] == 1
    [failed] = [r for r in report["records"] if not r["passed"]]
    assert (failed["fixture"], failed["kind"]) == ("04-ps-encoded.json", "negative")


def test_negative_without_rule_result_aborts_instead_of_passing(tmp_path):
    # No Phase 3 cannot tell "not fired" from "not evaluated" (see
    # HUMAN_ACTION_REQUIRED.md), so it must not be scored as "no alarm".
    code, report, output = run_cli(tmp_path, "no_rule_result")
    assert code == 1
    assert report is None
    assert "No rule result in logtest output" in output


@pytest.mark.parametrize("filename,rule_id", [(c[0], c[1]) for c in CASES])
def test_cases_exclude_correlation_rules(filename, rule_id):
    # Each event runs in a fresh wazuh-logtest process, so frequency-based
    # rules (e.g. SSH brute force 100110/100111) cannot be scored here.
    rules = {r.attrib["id"]: r for r in
             ElementTree.parse(ROOT / "detection-rules/custom-wazuh-rules.xml").getroot()}
    assert "frequency" not in rules[rule_id].attrib, filename
