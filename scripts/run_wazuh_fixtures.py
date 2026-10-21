"""Check real wazuh-logtest output on an explicitly selected isolated container.

Only feeds synthetic JSON to logtest. Does not run attack scripts, restart a
service, install rules or claim agent/indexer/AD or correlation coverage.
"""

import argparse
import copy
import json
import re
import subprocess
from pathlib import Path

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
        raise RuntimeError(f"No rule result in logtest output: {output}")
    return ids[-1], output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True, help="Your isolated Wazuh test container")
    parser.add_argument("--output", required=True, type=Path, help="New evidence JSON file")
    args = parser.parse_args()
    records = []
    for filename, expected, field, benign in CASES:
        event = json.loads((ROOT / "infrastructure/docker/test-events" / filename).read_text())
        actual, output = run(args.container, event)
        records.append({"fixture": filename, "kind": "positive", "expected": expected,
                        "actual": actual, "passed": actual == expected, "output": output})
        negative = copy.deepcopy(event)
        negative["win"]["eventdata"][field] = benign
        actual, output = run(args.container, negative)
        records.append({"fixture": filename, "kind": "negative", "excluded": expected,
                        "actual": actual, "passed": actual != expected, "output": output})
    report = {
        "scope": "Real logtest field/ancestry detection; no agent, AD, indexer or correlation claim",
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
