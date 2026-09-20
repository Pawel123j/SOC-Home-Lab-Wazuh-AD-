# Polecenia rozpoznania środowiska

## Technika ataku

Rozpoznanie po uzyskaniu dostępu: wyliczanie kont domenowych, grup
uprzywilejowanych, kontrolerów domeny i sesji sieciowych.

## Źródło logu

Sysmon EID 1 (`ProcessCreate`), pole `commandLine`.

## Logika detekcji

Dopasowanie linii poleceń do zestawu typowych poleceń rozpoznania:
`net group "Domain Admins"`, `nltest /dclist`, `whoami /groups`,
`net view /domain`, `Get-ADUser -Filter`, `Get-ADComputer -Filter`, `net session`.

Poziom 7 jest celowo niski: pojedyncze takie polecenie bywa uzasadnione,
a wartość reguły ujawnia się dopiero w korelacji (`100297`) i przy analizie
retrospektywnej.

## Reguła Wazuh

```xml
<rule id="100250" level="7">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(net\s+(group|user)\s+"?Domain Admins|nltest\s+/dclist|whoami\s+/groups|net\s+view\s+/domain|Get-ADUser\s+-Filter|Get-ADComputer\s+-Filter|net\s+session)</field>
  <description>Suspicious discovery command: $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1087.002</id>
    <id>T1018</id>
    <id>T1069.002</id>
  </mitre>
  <group>discovery,sysmon,</group>
</rule>
```

## Mapowanie MITRE ATT&CK

- `T1018`
- `T1069.002`
- `T1087.002`

## Oczekiwany alert

- `100250`, level 7 — pełna linia poleceń w treści alertu.

## Fałszywe alarmy

- **Administratorzy wykonują dokładnie te polecenia** w ramach normalnej pracy.
  To nie jest reguła do samodzielnego reagowania.
- Skrypty inwentaryzacyjne i narzędzia audytowe używają `Get-ADUser`
  i `Get-ADComputer` masowo.

## Ograniczenia

Reguła opiera się na dopasowaniu ciągów, więc omija ją każda zmiana zapisu:
skrócone parametry, użycie API zamiast poleceń, narzędzia takie jak BloodHound
zbierające te same dane przez LDAP bez uruchamiania `net`. Wykrycie zbierania
danych przez LDAP wymaga logowania zapytań na kontrolerze domeny — roadmapa.

## Walidacja

Co jest sprawdzane automatycznie przy każdym pushu
(`.github/workflows/validate.yml`):

- poprawność składni reguł i unikalność identyfikatorów,
- spójność łańcuchów `if_sid` / `if_matched_sid`,
- poprawność tagów MITRE,
- zgodność poziomów alertów w tej dokumentacji z definicjami reguł.

Czego **nie** sprawdza CI: czy reguła faktycznie wystrzeli na prawdziwym
zdarzeniu. To wymaga działającego managera Wazuh — procedura w
[04-detection-results.md](../04-detection-results.md), sekcja „Jak zmierzyć
to u siebie".

---

[← Spis scenariuszy](README.md)
