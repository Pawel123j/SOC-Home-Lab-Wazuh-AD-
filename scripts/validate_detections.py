#!/usr/bin/env python3
"""Walidator treści detekcyjnych tego repozytorium.

Uruchamiany w CI (.github/workflows/validate.yml) oraz lokalnie:

    python3 scripts/validate_detections.py

Sprawdza trzy rzeczy, których zepsucie jest w tym repo najbardziej kosztowne:

1. **Reguły Wazuh** (`detection-rules/custom-wazuh-rules.xml`) — poprawność XML,
   unikalność `id`, zakres ID zarezerwowany dla reguł własnych, obecność
   `level`, `description` i mapowania MITRE, oraz spójność łańcuchów
   `if_sid`/`if_matched_sid` w obrębie pliku.
2. **Reguły Sigma** (`detection-rules/sigma-rules/*.yml`) — poprawność YAML
   i obecność pól wymaganych przez specyfikację Sigma.
3. **Syntetyczne zdarzenia** (`infrastructure/docker/test-events/*.json`) —
   poprawny JSON i struktura Sysmona, której oczekują reguły.

CZEGO TEN SKRYPT NIE ROBI: nie uruchamia Wazuha, więc nie potwierdza, że
reguła *strzeli* na zdarzeniu — do tego potrzebny jest kontener z managerem
(`infrastructure/docker/`, patrz HUMAN_ACTION_REQUIRED.md). To walidacja
statyczna: łapie literówki, duplikaty ID i zerwane łańcuchy, zanim ktoś
postawi całe laboratorium.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

REPO = pathlib.Path(__file__).resolve().parent.parent

WAZUH_RULES = REPO / "detection-rules" / "custom-wazuh-rules.xml"
SIGMA_DIR = REPO / "detection-rules" / "sigma-rules"
EVENTS_DIR = REPO / "infrastructure" / "docker" / "test-events"

# Wazuh rezerwuje 100000+ dla reguł użytkownika; niższe ID kolidują
# z regułami wbudowanymi i zostaną nadpisane przy aktualizacji managera.
CUSTOM_ID_MIN = 100000
CUSTOM_ID_MAX = 120000

errors: list[str] = []
notes: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)


def check_wazuh_rules() -> None:
    if not WAZUH_RULES.exists():
        fail(f"{WAZUH_RULES.relative_to(REPO)}: plik nie istnieje")
        return

    try:
        root = ET.parse(WAZUH_RULES).getroot()
    except ET.ParseError as exc:
        fail(f"{WAZUH_RULES.relative_to(REPO)}: niepoprawny XML — {exc}")
        return

    if root.tag != "group":
        fail(f"{WAZUH_RULES.relative_to(REPO)}: element główny to <{root.tag}>, oczekiwano <group>")

    rules = root.findall(".//rule")
    if not rules:
        fail(f"{WAZUH_RULES.relative_to(REPO)}: nie znaleziono żadnej reguły")
        return

    seen: dict[str, int] = {}
    local_ids: set[str] = set()

    for rule in rules:
        rid = rule.get("id")
        if rid is None:
            fail("reguła Wazuh bez atrybutu id")
            continue
        local_ids.add(rid)

        if rid in seen:
            fail(f"reguła {rid}: zduplikowane id (występuje {seen[rid] + 1} raz/y)")
        seen[rid] = seen.get(rid, 0) + 1

        if not rid.isdigit():
            fail(f"reguła {rid}: id nie jest liczbą")
        elif not CUSTOM_ID_MIN <= int(rid) <= CUSTOM_ID_MAX:
            fail(
                f"reguła {rid}: id poza zakresem reguł własnych "
                f"({CUSTOM_ID_MIN}..{CUSTOM_ID_MAX}) — koliduje z regułami wbudowanymi Wazuha"
            )

        level = rule.get("level")
        if level is None:
            fail(f"reguła {rid}: brak atrybutu level")
        elif not level.isdigit() or not 0 <= int(level) <= 16:
            fail(f"reguła {rid}: level='{level}' poza dozwolonym zakresem 0..16")

        if rule.find("description") is None or not (rule.findtext("description") or "").strip():
            fail(f"reguła {rid}: brak niepustego <description>")

        if rule.find("mitre") is None:
            fail(f"reguła {rid}: brak mapowania <mitre> — wymagane w tym repozytorium")
        else:
            techniques = [t.text for t in rule.findall("mitre/id") if (t.text or "").strip()]
            if not techniques:
                fail(f"reguła {rid}: <mitre> bez żadnego <id>")
            for technique in techniques:
                if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique or ""):
                    fail(f"reguła {rid}: '{technique}' nie wygląda na technikę MITRE ATT&CK")

    # Łańcuchy if_sid: SID spoza pliku pochodzi z reguł wbudowanych Wazuha,
    # czego statycznie nie potwierdzimy — ale SID w zakresie własnym MUSI
    # istnieć w tym pliku, inaczej łańcuch jest zerwany.
    for rule in rules:
        rid = rule.get("id", "?")
        for tag in ("if_sid", "if_matched_sid"):
            for element in rule.findall(tag):
                for sid in (element.text or "").split(","):
                    sid = sid.strip()
                    if not sid:
                        continue
                    if sid.isdigit() and CUSTOM_ID_MIN <= int(sid) <= CUSTOM_ID_MAX:
                        if sid not in local_ids:
                            fail(
                                f"reguła {rid}: <{tag}>{sid}</{tag}> wskazuje na regułę własną, "
                                f"której nie ma w tym pliku — zerwany łańcuch"
                            )
                    elif sid.isdigit():
                        notes.append(f"reguła {rid}: {tag}={sid} → reguła wbudowana Wazuha (nie weryfikowane statycznie)")

    print(f"  Wazuh: {len(rules)} reguł, {len(local_ids)} unikalnych ID")


def check_sigma_rules() -> None:
    import yaml

    files = sorted(SIGMA_DIR.glob("*.yml")) + sorted(SIGMA_DIR.glob("*.yaml"))
    if not files:
        fail(f"{SIGMA_DIR.relative_to(REPO)}: nie znaleziono żadnej reguły Sigma")
        return

    # Minimum wymagane przez specyfikację Sigma.
    required = ("title", "logsource", "detection")

    for path in files:
        rel = path.relative_to(REPO)
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            fail(f"{rel}: niepoprawny YAML — {exc}")
            continue

        if not isinstance(doc, dict):
            fail(f"{rel}: reguła Sigma musi być mapą na najwyższym poziomie")
            continue

        for key in required:
            if key not in doc:
                fail(f"{rel}: brak wymaganego pola '{key}'")

        detection = doc.get("detection")
        if isinstance(detection, dict) and "condition" not in detection:
            fail(f"{rel}: sekcja 'detection' bez 'condition'")

        level = doc.get("level")
        if level is not None and level not in {"informational", "low", "medium", "high", "critical"}:
            fail(f"{rel}: level='{level}' spoza dozwolonych wartości Sigma")

        status = doc.get("status")
        if status is not None and status not in {"stable", "test", "experimental", "deprecated", "unsupported"}:
            fail(f"{rel}: status='{status}' spoza dozwolonych wartości Sigma")

    print(f"  Sigma: {len(files)} reguł")


def check_test_events() -> None:
    files = sorted(EVENTS_DIR.glob("*.json"))
    if not files:
        fail(f"{EVENTS_DIR.relative_to(REPO)}: nie znaleziono syntetycznych zdarzeń")
        return

    for path in files:
        rel = path.relative_to(REPO)
        try:
            event = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"{rel}: niepoprawny JSON — {exc}")
            continue

        # Reguły dopasowują się do dekodera Windows/Sysmon Wazuha, który
        # oczekuje win.system.eventID. Bez tego zdarzenie nie ma szans strzelić.
        win = event.get("win")
        if not isinstance(win, dict):
            fail(f"{rel}: brak obiektu 'win' — dekoder Wazuha go wymaga")
            continue

        system = win.get("system")
        if not isinstance(system, dict):
            fail(f"{rel}: brak 'win.system'")
            continue

        if not str(system.get("eventID", "")).strip():
            fail(f"{rel}: brak 'win.system.eventID'")

        if not str(system.get("channel", "")).strip():
            fail(f"{rel}: brak 'win.system.channel'")

    print(f"  Zdarzenia: {len(files)} plików JSON")


def main() -> int:
    print("Walidacja treści detekcyjnych SOC Home Lab")
    check_wazuh_rules()
    check_sigma_rules()
    check_test_events()

    if notes:
        print(f"\n  ({len(notes)} odwołań do reguł wbudowanych Wazuha — poza zasięgiem walidacji statycznej)")

    if errors:
        print(f"\nBŁĘDY ({len(errors)}):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("\nOK — wszystkie sprawdzenia przeszły.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
