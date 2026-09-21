# Utrwalenie przez zadanie zaplanowane

## Technika ataku

Zapewnienie sobie ponownego wykonania kodu przez utworzenie zadania w Task
Scheduler — przy logowaniu, przy starcie systemu albo cyklicznie. Popularna
technika post-exploitation, bo zadanie może działać jako `SYSTEM` i przetrwać
restart bez ingerencji w rejestrowe klucze `Run`.

## Źródło logu

Sysmon EID 1 (`ProcessCreate`), reguła wbudowana `61603`. Zdarzenie łapie
uruchomienie `schtasks.exe` wraz z pełną linią komend.

Alternatywą jest Security EID 4698 (*A scheduled task was created*), ale wymaga
włączonego audytu „Object Access → Other Object Access Events", domyślnie
wyłączonego. Lab i tak zbiera Sysmon EID 1 dla pozostałych reguł, więc to
źródło jest pierwszym wyborem; 4698 jest wymienione jako fallback w regule
Sigma.

## Logika detekcji

Trzy warunki `<field>` łączone przez AND:

1. `win.eventdata.image` kończy się na `\schtasks.exe`,
2. linia komend zawiera `/create`,
3. linia komend zawiera podejrzany ładunek: interpreter skryptów
   (`powershell`, `cmd.exe /c`, `mshta`, `rundll32`, `regsvr32`, `wmic`,
   `bitsadmin`), adres HTTP(S), ścieżkę zapisywalną przez użytkownika
   (`AppData\Local\Temp`, `C:\Users\Public`, `\Windows\Temp\`) albo
   uruchomienie jako `SYSTEM`.

Bez warunku (3) reguła strzelałaby na każdym legalnym zadaniu tworzonym przez
instalatory i administratorów. Warunek (3) to bezpośredni odpowiednik sekcji
`suspicious_payload` i `suspicious_run_as` z reguły Sigma.

## Reguła Wazuh

```xml
<rule id="100241" level="10">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\\\schtasks\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/create\b</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(powershell|cmd\.exe\s*/c|mshta|rundll32|regsvr32|wmic|bitsadmin|https?://|AppData\\\\Local\\\\Temp|C:\\\\Users\\\\Public|\\\\Windows\\\\Temp\\\\|/ru\s+"?(NT AUTHORITY\\\\)?SYSTEM)</field>
  <description>Scheduled task persistence: $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
  <group>persistence,sysmon,</group>
</rule>
```

## Mapowanie MITRE ATT&CK

- `T1053.005`

## Oczekiwany alert

- `100241`, level 10 — w treści alertu pełna linia komend, więc od razu widać,
  co zadanie ma uruchamiać i z jakimi uprawnieniami.

## Fałszywe alarmy

Filtr ładunku odsiewa większość legalnych zadań, ale nie wszystkie:

- Wdrożenia oprogramowania potrafią tworzyć zadania uruchamiane jako `SYSTEM`.
- Skrypty administracyjne owijane w `powershell` również trafią w warunek (3).

Strojenie: wykluczenie po skrócie rodzica (`parentImage`) albo koncie
uruchamiającym dla znanych narzędzi wdrożeniowych. Level 10 świadomie plasuje
regułę poniżej progu natychmiastowej eskalacji.

## Powiązana reguła Sigma

[`detection-rules/sigma-rules/suspicious-scheduled-task.yml`](../../detection-rules/sigma-rules/suspicious-scheduled-task.yml)
— ta sama logika w formacie przenośnym między systemami SIEM.

## Status weryfikacji

**NOT TESTED / REQUIRES LAB.** Sprawdzone statycznie: poprawność XML, składnia
pcre2 oraz dopasowanie wzorców do syntetycznego zdarzenia
[`11-scheduled-task.json`](../../infrastructure/docker/test-events/11-scheduled-task.json)
(trzy warunki trafiają, a legalne zadanie bez podejrzanego ładunku nie).
**Nie** sprawdzono, czy reguła faktycznie wystrzeli w managerze Wazuh — do tego
potrzebny jest kontener z managerem (patrz `HUMAN_ACTION_REQUIRED.md`).

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
