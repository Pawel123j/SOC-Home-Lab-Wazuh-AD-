# mshta.exe jako proxy wykonania (LOLBAS)

## Technika ataku

Wykorzystanie `mshta.exe` — komponentu systemowego do uruchamiania aplikacji HTA —
do wykonania kodu z pominięciem kontroli aplikacji. Wariant zdalny pobiera HTA
spod adresu URL, wariant lokalny uruchamia interpreter poleceń.

## Źródło logu

Sysmon EID 1 (`ProcessCreate`), pola `image`, `commandLine`, `parentImage`.

## Logika detekcji

`100220` szuka `mshta.exe` z adresem URL w linii poleceń — wykonanie kodu wprost
z sieci.

`100221` jest mocniejsza i opiera się na **relacji rodzic–dziecko**, a nie na samym
uruchomieniu `mshta`: alarmuje, gdy `mshta.exe` jest rodzicem `powershell.exe`,
`cmd.exe`, `wscript.exe` albo `cscript.exe`.

Powód wysokiej konfidencji: `mshta.exe` uruchamiający interpreter poleceń nie ma
praktycznie zastosowań w nowoczesnym środowisku Windows. Aplikacje HTA były
normalne kilkanaście lat temu; dziś ten łańcuch procesów to niemal zawsze technika
omijania kontroli aplikacji.

## Reguła Wazuh

```xml
<rule id="100220" level="12">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\\\mshta\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)mshta(\.exe)?\s+(https?:|//|ftp:)</field>
  <description>mshta.exe executing remote HTA file: $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1218.005</id>
  </mitre>
  <group>defense_evasion,execution,lolbas,sysmon,</group>
</rule>

<rule id="100221" level="13">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)\\\\mshta\.exe$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)\\\\(powershell(_ise)?|cmd|wscript|cscript)\.exe$</field>
  <description>mshta.exe spawned script interpreter $(win.eventdata.image): classic LOLBAS chain</description>
  <mitre>
    <id>T1218.005</id>
    <id>T1059</id>
  </mitre>
  <group>defense_evasion,execution,lolbas,sysmon,attack,</group>
</rule>
```

## Mapowanie MITRE ATT&CK

- `T1059`
- `T1218.005`

## Oczekiwany alert

- `100220`, level 12 — pełna linia poleceń z adresem URL w treści alertu.
- `100221`, level 13 — łańcuch procesów widoczny wprost w polach `parentImage`
  i `image`.

Level 13, a nie 15 — najwyższy poziom rezerwujemy na potwierdzone niszczenie
danych i ransomware.

## Fałszywe alarmy

- **Starsze aplikacje wewnętrzne.** Jedyne realne źródło fałszywych alarmów:
  systemy firmowe z czasów, gdy HTA było standardem. Jeżeli takie istnieją,
  rozpoznaje się je po stałej, powtarzalnej ścieżce pliku HTA i wyklucza po niej.
- W środowisku bez takich aplikacji `100221` powinna być praktycznie wolna
  od fałszywych alarmów — co czyni ją dobrą regułą do reakcji automatycznej,
  gdyby ją włączać.

## Ograniczenia

Reguła obejmuje cztery interpretery. Napastnik może użyć `mshta` do uruchomienia
własnego binarium zamiast interpretera — wtedy `100221` nie zadziała, a `100220`
tylko wtedy, gdy HTA było pobierane zdalnie.

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
