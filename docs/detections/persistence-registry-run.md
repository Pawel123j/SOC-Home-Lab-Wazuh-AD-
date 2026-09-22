# Utrwalenie przez klucz Run w rejestrze

## Technika ataku

Zapewnienie sobie ponownego uruchomienia po restarcie przez dodanie wartości
do klucza `Run` albo `RunOnce` w rejestrze.

## Źródło logu

Sysmon EID 13 (`RegistryEvent — value set`), reguła wbudowana `61615`.

## Logika detekcji

Dopasowanie ścieżki klucza do `...\Microsoft\Windows\CurrentVersion\Run(Once)\`,
z obsługą gałęzi `Wow6432Node` dla aplikacji 32-bitowych na systemie 64-bitowym.
Pominięcie `Wow6432Node` to typowe przeoczenie, przez które technika przechodzi
niezauważona na maszynach 64-bitowych.

## Reguła Wazuh

```xml
<rule id="100240" level="9">
  <if_sid>61615</if_sid>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run(Once)?\\\\</field>
  <description>Registry persistence: new value in Run key: $(win.eventdata.targetObject) = $(win.eventdata.details)</description>
  <mitre>
    <id>T1547.001</id>
  </mitre>
  <group>persistence,sysmon,</group>
</rule>
```

## Mapowanie MITRE ATT&CK

- `T1547.001`

## Oczekiwany alert

- `100240`, level 9 — w treści alertu ścieżka klucza i **ustawiana wartość**
  (`win.eventdata.details`), czyli od razu widać, co ma się uruchamiać.

## Fałszywe alarmy

**To reguła szumna z natury** i level 9 jest tego świadomym odzwierciedleniem —
poniżej progu natychmiastowej eskalacji.

- Każdy instalator dopisujący program do autostartu wyzwoli tę regułę.
- Aktualizacje oprogramowania przepisują swoje wpisy.

Wartość tej reguły jest **retrospektywna**: gdy inna reguła wskaże host jako
podejrzany, historia zmian w kluczach `Run` odpowiada na pytanie „czy napastnik
się utrwalił". Jako samodzielny alert nadaje się głównie do przeglądu okresowego.

## Ograniczenia

`Run`/`RunOnce` to jedna z kilkudziesięciu technik utrwalenia. Reguła nie obejmuje
usług, WMI ani folderu Autostart. Zadania zaplanowane mają osobną regułę
`100241` ([persistence-scheduled-task.md](persistence-scheduled-task.md)).

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
