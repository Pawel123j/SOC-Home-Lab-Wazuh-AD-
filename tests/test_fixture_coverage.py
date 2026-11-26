"""Every single-event custom rule has a positive fixture and a neutral control.

Single-event = no frequency, if_matched_sid, if_group or if_matched_group: one
decoded event is enough to evaluate it, so it must be listed in CASES. The
positive/neutral PCRE2 check itself is test_field_patterns.py; the real-manager
run is scripts/run_wazuh_fixtures.py. Correlation rules need an event sequence
and are out of scope here (see HUMAN_ACTION_REQUIRED.md).
"""

import sys
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import run_wazuh_fixtures  # noqa: E402
import test_field_patterns  # noqa: E402

RULES = list(ElementTree.parse(ROOT / "detection-rules/custom-wazuh-rules.xml").getroot().iter("rule"))
CORRELATION_TAGS = ("if_matched_sid", "if_group", "if_matched_group")


def single_event_rule_ids():
    return {
        rule.get("id") for rule in RULES
        if rule.get("frequency") is None
        and not any(rule.find(tag) is not None for tag in CORRELATION_TAGS)
        and rule.findall("field")
    }


def test_both_case_tables_are_identical():
    assert run_wazuh_fixtures.CASES == test_field_patterns.CASES


def test_every_single_event_rule_has_positive_and_neutral_case():
    covered = {rule_id for _, rule_id, *_ in test_field_patterns.CASES}
    assert sorted(single_event_rule_ids() - covered) == []


def test_every_fixture_file_is_used():
    files = {path.name for path in (ROOT / "infrastructure/docker/test-events").glob("*.json")}
    assert sorted(files - {name for name, *_ in test_field_patterns.CASES}) == []
