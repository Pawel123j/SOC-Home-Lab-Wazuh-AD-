"""Score the synthetic fixtures on an explicitly selected isolated Wazuh container.

Two transports:

* ``logtest`` (default) pipes each fixture into ``wazuh-logtest``. In Wazuh 4.7
  logtest never calls the Windows EventChannel decoder (it always builds a
  ``1:<location>:<log>`` message), so Windows fixtures stop with an explicit
  error instead of a result.
* ``eventchannel`` sends each fixture to the manager's analysisd queue in the
  format a Windows agent uses (``f:EventChannel:{"Message":..,"Event":"<Event>"}``),
  so the real ``windows_eventchannel`` decoder and built-in rule chain run.
  Every event is proven evaluated by its line in ``archives.json`` (decoder
  ``windows_eventchannel``); a missing line is an error, never a pass. Needs
  ``<logall_json>yes</logall_json>`` in the container's ossec.conf.

Only feeds synthetic events. Does not run attack scripts, restart a service,
install rules or claim agent/indexer/AD or correlation coverage. Stops before
the first manager call if a fixture lacks the win.eventdata field its negative
sample replaces.
"""

import argparse
import copy
import json
import re
import subprocess
import time
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("02-lsass-access.json", "100210", "targetImage", r"C:\Windows\System32\notepad.exe"),
    ("03-lsass-comsvcs.json", "100211", "commandLine", "rundll32.exe shell32.dll,Control_RunDLL"),
    ("04-ps-encoded.json", "100212", "commandLine", "powershell.exe -NoProfile Get-Date"),
    ("05-ps-network.json", "100213", "destinationIp", "127.0.0.1"),
    ("06-ps-iex-download.json", "100214", "scriptBlockText", "Write-Output 'hello'"),
    ("07-mshta-remote.json", "100220", "commandLine", r"mshta.exe C:\local.hta"),
    ("08-mshta-child.json", "100221", "parentImage", r"C:\Windows\explorer.exe"),
    ("09-archive-temp.json", "100232", "targetFilename", r"C:\Users\Public\note.txt"),
    ("10-registry-run.json", "100240", "targetObject", r"HKLM\Software\Example\Setting"),
    ("11-scheduled-task.json", "100241", "commandLine", "schtasks.exe /query"),
    ("12-discovery-whoami.json", "100250", "commandLine", "whoami /user"),
]


def run(container, event):
    result = subprocess.run(
        ["docker", "exec", "-i", container, "/var/ossec/bin/wazuh-logtest"],
        input=json.dumps(event) + "\n", text=True, capture_output=True, timeout=30,
    )
    output = result.stdout + result.stderr
    if result.returncode or "ERROR" in output or "CRITICAL" in output:
        raise RuntimeError(f"logtest failed ({result.returncode}): {output}")
    ids = re.findall(r"(?:Rule id|id):\s*'(\d+)'", output)
    if not ids:
        if "win.system.channel" in output and "name: 'json'" in output:
            raise RuntimeError(
                "Windows Event Channel fixture was decoded as generic JSON; "
                "wazuh-logtest did not evaluate its Windows rules. Use "
                "--transport eventchannel or a real Windows agent instead."
            )
        raise RuntimeError(f"No rule result in logtest output: {output}")
    return ids[-1], output


LOGS = "/var/ossec/logs"
ARCHIVES, ALERTS = "archives/archives.json", "alerts/alerts.json"
MANAGER_PYTHON = "/var/ossec/framework/python/bin/python3"
INJECT = (
    "import socket, sys\n"
    "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n"
    "for line in sys.stdin.buffer.read().splitlines():\n"
    "    s.sendto(b'f:EventChannel:' + line, '/var/ossec/queue/sockets/queue')\n"
)
# Computed by the manager from Level/Keywords and the rendered message.
DERIVED_SYSTEM_FIELDS = {"severityValue", "message"}
ATTRIBUTES = {
    "providerName": ("Provider", "Name"), "providerGuid": ("Provider", "Guid"),
    "eventSourceName": ("Provider", "EventSourceName"),
    "systemTime": ("TimeCreated", "SystemTime"),
    "processID": ("Execution", "ProcessID"), "threadID": ("Execution", "ThreadID"),
}


def wazuh_decoded(value):
    """Return a raw Windows value the way Wazuh 4.7 stores it in win.* fields.

    The manager re-prints the agent's JSON-escaped event and parses that text
    as XML without decoding entities. So backslashes come out doubled, quotes
    as \\", and &, <, > as XML entities. Observed on wazuh-manager 4.7.5:
    '"C:\\Windows\\x.exe" & <y>' is stored as '\\"C:\\\\Windows\\\\x.exe\\" &amp; &lt;y&gt;'.
    Rule patterns must match this form, as Wazuh's own rules do.
    """
    return json.dumps(escape(str(value)), ensure_ascii=False)[1:-1]


def _attr(value):
    # Windows renders attributes in single quotes; the manager's XML parser
    # needs that, because it reads the JSON-escaped event text.
    return "'" + escape(str(value), {"'": "&apos;"}) + "'"


def to_eventchannel(event):
    """Render a decoded fixture as the JSON line a Windows agent sends."""
    system, eventdata = event["win"]["system"], event["win"]["eventdata"]
    attributes, elements = {}, []
    for key, value in system.items():
        if key in DERIVED_SYSTEM_FIELDS or str(value) == "":
            continue
        if key in ATTRIBUTES:
            tag, name = ATTRIBUTES[key]
            attributes.setdefault(tag, []).append(f"{name}={_attr(value)}")
        else:
            tag = key[0].upper() + key[1:]
            elements.append(f"<{tag}>{escape(str(value))}</{tag}>")
    head = "".join(f"<{tag} {' '.join(attrs)}/>" for tag, attrs in attributes.items())
    data = "".join(
        f"<Data Name={_attr(key[0].upper() + key[1:])}>{escape(str(value))}</Data>"
        for key, value in eventdata.items() if str(value) != ""
    )
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
           f"<System>{head}{''.join(elements)}</System><EventData>{data}</EventData></Event>")
    return json.dumps({"Message": system.get("message", ""), "Event": xml}, ensure_ascii=False)


def _exec(container, *command, stdin=None):
    result = subprocess.run(["docker", "exec", "-i", container, *command],
                            input=stdin, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"docker exec failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def _line_count(container, name):
    # A log the manager has not created yet has no lines.
    return int(_exec(container, "sh", "-c", f"wc -l < {LOGS}/{name} 2>/dev/null || echo 0").strip() or 0)


def _entries_after(container, name, start):
    output = _exec(container, "sh", "-c", f"tail -n +{start + 1} {LOGS}/{name} 2>/dev/null || true")
    # The manager may still be writing the last line; only "\n"-terminated
    # lines are complete. The next poll reads the rest.
    complete = output.split("\n")[:-1]
    return [json.loads(line) for line in complete if line.strip()]


def _record_id(entry):
    return entry.get("data", {}).get("win", {}).get("system", {}).get("eventRecordID")


def run_eventchannel(container, events, expect_alert=(), timeout=30.0, grace=1.0):
    """Send events like a Windows agent; return (alert rule id or None, decoder) per event.

    Waits until every event has its archives.json line and every index in
    expect_alert has an alert (or the timeout passes), then ``grace`` seconds
    more for late alerts.
    """
    if "<logall_json>yes</logall_json>" not in _exec(container, "cat", "/var/ossec/etc/ossec.conf"):
        raise RuntimeError(
            "archives.json is off, so evaluation cannot be proven: set "
            "<logall_json>yes</logall_json> in this test container's ossec.conf "
            "and restart its manager once"
        )
    run_id = str(time.time_ns() // 1000)
    tags, lines = [], []
    for index, event in enumerate(events):
        tag = f"{run_id}{index:04d}"   # unique per event, found again in archives/alerts
        tagged = copy.deepcopy(event)
        tagged["win"]["system"]["eventRecordID"] = tag
        tags.append(tag)
        lines.append(to_eventchannel(tagged))
    start = {name: _line_count(container, name) for name in (ARCHIVES, ALERTS)}
    _exec(container, MANAGER_PYTHON, "-c", INJECT, stdin="\n".join(lines) + "\n")
    wanted, alert_tags = set(tags), {tags[i] for i in expect_alert}
    decoders, alerts = {}, {}
    deadline = time.monotonic() + timeout
    while True:
        for entry in _entries_after(container, ARCHIVES, start[ARCHIVES]):
            if _record_id(entry) in wanted:
                decoders[_record_id(entry)] = entry.get("decoder", {}).get("name")
        for entry in _entries_after(container, ALERTS, start[ALERTS]):
            if _record_id(entry) in wanted:
                alerts[_record_id(entry)] = entry["rule"]["id"]
        if len(decoders) == len(wanted) and alert_tags <= alerts.keys():
            break
        if time.monotonic() > deadline:
            if len(decoders) < len(wanted):
                raise RuntimeError(f"manager did not process {len(wanted) - len(decoders)} event(s) "
                                   f"within {timeout:g}s; no result is reported for them")
            break
        time.sleep(0.5)
    time.sleep(grace)
    for entry in _entries_after(container, ALERTS, start[ALERTS]):
        if _record_id(entry) in wanted:
            alerts[_record_id(entry)] = entry["rule"]["id"]
    other = sorted({name for name in decoders.values() if name != "windows_eventchannel"}, key=str)
    if other:
        raise RuntimeError(f"events were decoded as {other}, not windows_eventchannel; "
                           "the Windows rules were not evaluated")
    return [(alerts.get(tag), decoders[tag]) for tag in tags]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--container", required=True, help="Your isolated Wazuh test container")
    parser.add_argument("--output", required=True, type=Path, help="New evidence JSON file")
    parser.add_argument("--transport", choices=("logtest", "eventchannel"), default="logtest",
                        help="How fixtures reach the manager (default: logtest)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="eventchannel: seconds to wait for the manager (default: 30)")
    args = parser.parse_args()
    events = {}
    for filename, _expected, field, _benign in CASES:
        event = json.loads((ROOT / "infrastructure/docker/test-events" / filename).read_text())
        # The negative replaces this field. If it is absent, assignment would
        # add a new key and leave the matched value in place, so the run would
        # blame the rule (FN/FP) for a broken fixture or case.
        if field not in event.get("win", {}).get("eventdata", {}):
            raise SystemExit(f"{filename}: no win.eventdata.{field}; fix the fixture or CASES")
        events[filename] = event
    samples = []
    for filename, expected, field, benign in CASES:
        negative = copy.deepcopy(events[filename])
        negative["win"]["eventdata"][field] = benign
        samples += [(filename, "positive", expected, events[filename]),
                    (filename, "negative", expected, negative)]
    if args.transport == "eventchannel":
        results = run_eventchannel(
            args.container, [event for *_, event in samples], timeout=args.timeout,
            expect_alert=[i for i, (_, kind, *_) in enumerate(samples) if kind == "positive"],
        )
        details = [{"decoder": decoder} for _, decoder in results]
        actuals = [actual for actual, _ in results]
        scope = ("Real manager: Windows EventChannel decoder and built-in rule chain on "
                 "synthetic events; no agent, AD, indexer or correlation claim")
    else:
        actuals, details = [], []
        for *_, event in samples:
            actual, output = run(args.container, event)
            actuals.append(actual)
            details.append({"output": output})
        scope = "Real logtest field/ancestry detection; no agent, AD, indexer or correlation claim"
    records = []
    for (filename, kind, expected, _), actual, detail in zip(samples, actuals, details):
        passed = actual == expected if kind == "positive" else actual != expected
        records.append({"fixture": filename, "kind": kind,
                        ("expected" if kind == "positive" else "excluded"): expected,
                        "actual": actual, "passed": passed, **detail})
    report = {
        "scope": scope,
        "false_negatives": sum(not r["passed"] for r in records if r["kind"] == "positive"),
        "false_positives": sum(not r["passed"] for r in records if r["kind"] == "negative"),
        "records": records,
    }
    with args.output.open("x", encoding="utf-8") as target:
        json.dump(report, target, indent=2)
    print(f"FN={report['false_negatives']}; FP={report['false_positives']}; {len(records)} cases")
    return int(any(not r["passed"] for r in records))


if __name__ == "__main__":
    raise SystemExit(main())
