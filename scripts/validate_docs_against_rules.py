#!/usr/bin/env python3
"""Sprawdza, czy dokumentacja detekcji zgadza się z regułami w repozytorium.

Powód istnienia tego skryptu: dokumentacja opisująca detekcje rozjeżdża się
z regułami po cichu. Reguła dostaje inny próg albo poziom, a zdanie w dokumencie
zostaje stare — i nikt tego nie zauważa, bo nic się nie psuje. W projekcie
z obszaru bezpieczeństwa to kosztowne inaczej niż zwykły błąd w dokumentacji:
opis detekcji, który nie zgadza się z regułą, podważa wiarygodność całego
zestawu reguł, także tych poprawnych.

Skrypt sprawdza dwie rzeczy:

1. **Zgodność** — każdy poziom alertu i tag MITRE wymieniony w tabelach
   dokumentacji musi odpowiadać definicji reguły w XML-u.
2. **Brak zmyślonych dowodów** — dokumentacja nie może zawierać wskaźników
   TP/FP ani liczników trafień, dopóki nie pochodzą z opisanego przebiegu.
   Laboratorium wymaga trzech maszyn wirtualnych i nie da się go uruchomić
   w CI, więc takie liczby nie mają tu skąd pochodzić.

Kod wyjścia 0, gdy wszystko się zgadza; 1 w przeciwnym razie.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import defusedxml.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
RULES_XML = ROOT / "detection-rules" / "custom-wazuh-rules.xml"
DOCS_DIR = ROOT / "docs"

# Zakres reguł własnych jak CUSTOM_ID_MIN..CUSTOM_ID_MAX w validate_detections.py.
# Wcześniej 10\d{4} (100000..109999): cytat brakującej reguły 110001..120000
# przechodził bez błędu.
RULE_ID = r"(?:1[01]\d{4}|120000)"

# Wzorce, które sygnalizują wynik podany jako zaobserwowany. Jeżeli kiedyś
# laboratorium zostanie faktycznie uruchomione, wyniki wchodzą do dokumentu
# razem z datą i czasem trwania pomiaru — wtedy ten wzorzec trzeba poluzować
# świadomie, a nie przy okazji.
FABRICATED_EVIDENCE = [
    (r"\d+\s*TP\s*/\s*\d+\s*FP", "wskaźnik TP/FP bez opisanego przebiegu"),
    (r"\[Screenshot[: ]", "opis zrzutu ekranu zamiast zrzutu"),
]


def parse_rules(xml_text: str) -> dict[str, dict]:
    # Parser XML, nie regex: <id> w komentarzu wewnątrz <mitre> nie jest
    # techniką ani dla Wazuha, ani dla validate_detections.py.
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    rules: dict[str, dict] = {}
    for rule in root.iter("rule"):
        rule_id, level = rule.get("id", ""), rule.get("level", "")
        if not re.fullmatch(r"\d+", rule_id):
            continue
        rules[rule_id] = {
            "level": level if re.fullmatch(r"\d+", level) else None,
            "mitre": {element.text or "" for element in rule.findall("mitre/id")},
        }
    return rules


def check_document(path: Path, rules: dict[str, dict]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    name = path.relative_to(ROOT)
    problems: list[str] = []

    # Reguły cytowane w dokumencie muszą istnieć.
    for rule_id in sorted(set(re.findall(r"\b(" + RULE_ID + r")\b", text))):
        if rule_id not in rules:
            problems.append(f"{name}: cytuje nieistniejącą regułę {rule_id}")

    # Wiersze tabel postaci: | `100xxx` | <poziom> | <warunek> | <MITRE> |
    row = re.compile(
        r"^\|\s*\*{0,2}`(" + RULE_ID + r")`\*{0,2}\s*\|\s*\*{0,2}(\d+)\*{0,2}\s*\|(.*?)\|\s*([^|]*?)\s*\|\s*$",
        re.M,
    )
    for rule_id, level, _condition, mitre_cell in row.findall(text):
        rule = rules.get(rule_id)
        if rule is None:
            continue
        if rule["level"] != level:
            problems.append(
                f"{name}: reguła {rule_id} opisana jako level {level}, "
                f"a w XML ma level {rule['level']}"
            )
        cited = set(re.findall(r"T\d+(?:\.\d+)?", mitre_cell))
        if cited and cited != rule["mitre"]:
            problems.append(
                f"{name}: reguła {rule_id} ma w dokumencie MITRE {sorted(cited)}, "
                f"a w XML {sorted(rule['mitre'])}"
            )

    # Zapis prozą: `100210`, level 14 — używany w sekcjach „Oczekiwany alert".
    for rule_id, level in re.findall(r"`(" + RULE_ID + r")`[^\n]{0,40}?level (\d+)", text):
        rule = rules.get(rule_id)
        if rule and rule["level"] != level:
            problems.append(
                f"{name}: reguła {rule_id} opisana w tekście jako level {level}, "
                f"a w XML ma level {rule['level']}"
            )

    for pattern, label in FABRICATED_EVIDENCE:
        hits = len(re.findall(pattern, text))
        if hits:
            problems.append(f"{name}: {label} ({hits}×)")

    return problems


def main() -> int:
    if not RULES_XML.is_file():
        print(f"Brak pliku reguł: {RULES_XML}", file=sys.stderr)
        return 1

    rules = parse_rules(RULES_XML.read_text(encoding="utf-8"))
    if not rules:
        print("Nie udało się sparsować żadnej reguły — sprawdź XML.", file=sys.stderr)
        return 1

    documents = sorted(DOCS_DIR.rglob("*.md"))
    if not documents:
        # Pusty zestaw niczego nie sprawdza — to nie jest sukces.
        print(
            f"Nie znaleziono żadnego dokumentu w {DOCS_DIR.relative_to(ROOT)}/",
            file=sys.stderr,
        )
        return 1

    problems: list[str] = []
    for document in documents:
        problems.extend(check_document(document, rules))

    if problems:
        print(f"Niezgodności dokumentacji z regułami: {len(problems)}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"OK — {len(documents)} dokumentów zgodnych z {len(rules)} regułami.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
