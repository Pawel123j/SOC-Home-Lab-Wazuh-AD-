# Utrwalenie przez klucz Run w rejestrze

## Technika ataku

Zapewnienie sobie ponownego uruchomienia po restarcie przez dodanie wartości
do klucza `Run` albo `RunOnce` w rejestrze.

## Źródło logu

Sysmon EID 13 (`RegistryEvent — value set`), reguła wbudowana `61615`.

Każda zmiana klucza `Run` trafia w Wazuh 4.7 najpierw do wbudowanej reguły
`92300` (level 0, „Added registry content to be executed on next logon"),
a zapis przez `reg.exe` dalej do `92302`. Wazuh sprawdza te wbudowane reguły
przed naszą, więc `100240` jako dziecko `61615` nigdy by nie strzeliła —
dlatego wisi pod `92300` i `92302`. Separatory ścieżki we wzorcu to `\\\\`,
bo Wazuh przechowuje każdy `\` z wartości rejestru podwojony.

## Logika detekcji

Dopasowanie ścieżki klucza do `...\Microsoft\Windows\CurrentVersion\Run(Once)\`,
z obsługą gałęzi `Wow6432Node` dla aplikacji 32-bitowych na systemie 64-bitowym.
Pominięcie `Wow6432Node` to typowe przeoczenie, przez które technika przechodzi
niezauważona na maszynach 64-bitowych.

## Reguła Wazuh

```xml
<rule id="100240" level="9">
  <if_sid>92300, 92302</if_sid>
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

Na prawdziwym managerze Wazuh 4.7.5 (job „Prawdziwy Wazuh manager" w CI,
`scripts/run_wazuh_fixtures.py --transport eventchannel`) sprawdzane jest, że
`100240` strzela na syntetycznej fiksturze, a nie strzela na próbce neutralnej.

Czego **nie** sprawdza CI: zbierania zdarzenia przez agenta i Sysmona na
prawdziwym Windowsie. Procedura w
[04-detection-results.md](../04-detection-results.md), sekcja „Jak zmierzyć
to u siebie".

---

[← Spis scenariuszy](README.md)
