"""--transport eventchannel through the CLI, with a local fake manager.

The fake `docker` plays wazuh-manager: it reads the agent-format lines sent to
the analysis queue, decodes them like Wazuh 4.7 (wazuh_decoded), evaluates
only the <field> PCRE2 patterns of the rules in CASES and appends to fake
archives.json / alerts.json. It is not Wazuh; the real-manager run is the CI
job "Prawdziwy Wazuh manager" and HUMAN_ACTION_REQUIRED.md.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/run_wazuh_fixtures.py"
sys.path.insert(0, str(ROOT / "scripts"))
from run_wazuh_fixtures import CASES, to_eventchannel  # noqa: E402

FAKE_MANAGER = f"""#!{sys.executable}
import json, os, pathlib, subprocess, sys
from xml.etree import ElementTree
import pcre2
sys.path.insert(0, {str(ROOT / "scripts")!r})
from run_wazuh_fixtures import CASES, ROOT, wazuh_decoded
state = pathlib.Path(os.environ["FAKE_STATE"])
mode = os.environ.get("FAKE_MODE", "ok")
args = sys.argv[1:]
assert args[:2] == ["exec", "-i"], args
command = args[3:]
logs = state / "logs"

def path(p):
    return logs / p.split("/var/ossec/logs/", 1)[1]

if command[:2] == ["cat", "/var/ossec/etc/ossec.conf"]:
    print("<logall_json>no</logall_json>" if mode == "archives_off" else "<logall_json>yes</logall_json>")
elif command[:2] == ["sh", "-c"] and command[2].startswith("wc -l < "):
    p = path(command[2].split("< ", 1)[1].split(" ", 1)[0])
    print(len(p.read_text().splitlines()) if p.exists() else 0)
elif command[:2] == ["sh", "-c"] and command[2].startswith("tail -n +"):
    start, name = command[2][len("tail -n +"):].split(" ")[:2]
    p = path(name)
    lines = p.read_text().splitlines(True) if p.exists() else []
    sys.stdout.write("".join(lines[int(start) - 1:]))
elif command[0].endswith("python3"):
    rules = {{r.get("id"): r for r in
             ElementTree.parse(ROOT / "detection-rules/custom-wazuh-rules.xml").getroot().iter("rule")}}
    (logs / "archives").mkdir(parents=True, exist_ok=True); (logs / "alerts").mkdir(parents=True, exist_ok=True)
    for line in sys.stdin.read().splitlines():
        if mode == "drop":
            continue
        root = ElementTree.fromstring(json.loads(line)["Event"])
        ns = "{{http://schemas.microsoft.com/win/2004/08/events/event}}"
        system, data = {{}}, {{}}
        for el in root.find(ns + "System"):
            tag = el.tag.replace(ns, "")
            if el.attrib:
                for k, v in el.attrib.items():
                    system[{{"Name": "providerName", "Guid": "providerGuid", "SystemTime": "systemTime",
                             "ProcessID": "processID", "ThreadID": "threadID",
                             "EventSourceName": "eventSourceName"}}[k]] = wazuh_decoded(v)
            else:
                system[tag[0].lower() + tag[1:]] = wazuh_decoded(el.text or "")
        for el in root.find(ns + "EventData"):
            name = el.attrib["Name"]
            data[name[0].lower() + name[1:]] = wazuh_decoded(el.text or "")
        event = {{"win": {{"system": system, "eventdata": data}}}}
        decoder = "json" if mode == "generic_json" else "windows_eventchannel"
        with (logs / "archives/archives.json").open("a") as out:
            out.write(json.dumps({{"decoder": {{"name": decoder}}, "data": event}}) + "\\n")
        for _, rule_id, *_ in CASES:
            fields = rules[rule_id].findall("field")
            names = [f.get("name").split(".")[-1] for f in fields]
            if all(n in data and pcre2.search(f.text, data[n]) for n, f in zip(names, fields)):
                with (logs / "alerts/alerts.json").open("a") as out:
                    out.write(json.dumps({{"rule": {{"id": rule_id}}, "data": event}}) + "\\n")
                break
else:
    sys.exit(f"fake docker: unexpected {{command}}")
"""


def run_cli(tmp_path, mode="ok", timeout="30"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(FAKE_MANAGER)
    (bin_dir / "docker").chmod(0o755)
    report = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--container", "isolated-test", "--transport", "eventchannel",
         "--timeout", timeout, "--output", str(report)],
        capture_output=True, text=True, timeout=120,
        env=dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                 FAKE_STATE=str(tmp_path), FAKE_MODE=mode),
    )
    data = json.loads(report.read_text()) if report.exists() else None
    return result.returncode, result.stdout + result.stderr, data


def test_all_fixtures_scored_through_eventchannel_decoder(tmp_path):
    code, output, report = run_cli(tmp_path)
    assert code == 0, output
    assert (report["false_negatives"], report["false_positives"]) == (0, 0)
    assert len(report["records"]) == 2 * len(CASES)
    assert {r["decoder"] for r in report["records"]} == {"windows_eventchannel"}
    assert "output" not in report["records"][0]   # no raw log lines in the evidence file


@pytest.mark.parametrize("mode,message", [
    ("archives_off", "archives.json is off"),
    ("drop", f"manager did not process {2 * len(CASES)} event(s)"),
    ("generic_json", "not windows_eventchannel"),
])
def test_unproven_evaluation_is_an_error_not_a_result(tmp_path, mode, message):
    code, output, report = run_cli(tmp_path, mode=mode, timeout="2")
    assert code == 1
    assert message in output
    assert report is None


@pytest.mark.parametrize("filename", [case[0] for case in CASES])
def test_agent_format_round_trips_every_field(filename):
    event = json.loads((ROOT / "infrastructure/docker/test-events" / filename).read_text())
    line = json.loads(to_eventchannel(event))
    # The manager parses the JSON-escaped text, so attributes must use single quotes.
    assert '="' not in line["Event"]
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    root = ElementTree.fromstring(line["Event"])
    names = {el.attrib["Name"]: el.text for el in root.find(ns + "EventData")}
    expected = {k[0].upper() + k[1:]: v for k, v in event["win"]["eventdata"].items() if v != ""}
    assert names == expected
    system = {el.tag.replace(ns, ""): el for el in root.find(ns + "System")}
    # severityValue (rule 61600 and others) is derived only when both are present.
    assert system["Level"].text and system["Keywords"].text
    assert system["Channel"].text == event["win"]["system"]["channel"]
