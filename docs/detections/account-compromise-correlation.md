# Korelacja: włamanie na hosta Windows poprzedzające rozpoznanie

## Technika ataku

Wzorzec przejętego hosta: najpierw udany atak na hasło zdalnej usługi
(RDP/SMB), potem rozpoznanie środowiska Active Directory wykonane z wnętrza
tej samej maszyny. Rozpoznanie tuż po włamaniu to inny sygnał niż `whoami`
wykonane przez administratora w środku dnia pracy.

## Źródło logu

Pochodna — reguła nadbudowuje alerty `100120` (brute force RDP/SMB) i `100250`
(polecenia rozpoznania). Nie analizuje żadnego surowego zdarzenia; działa
wyłącznie na wyjściu innych reguł.

## Logika detekcji

`100297` strzela, gdy w oknie 1800 s po alercie `100120` pojawią się co
najmniej dwa alerty `100250` **z tego samego hosta**. Klucz korelacji to
`same_field agent.name` — oba zdarzenia muszą pochodzić od tego samego agenta
Wazuha. Pole `agent.name` istnieje w każdym zdarzeniu niezależnie od kanału
logu, więc korelacja działa między zdarzeniem Security (4625, brute force)
a Sysmonem (EID 1, rozpoznanie), które trafiają różnymi kanałami.

## Reguła Wazuh

```xml
<rule id="100297" level="13" frequency="2" timeframe="1800">
  <if_sid>100250</if_sid>
  <if_matched_sid>100120</if_matched_sid>
  <same_field>agent.name</same_field>
  <description>Likely account compromise on $(agent.name): Windows brute force followed by AD recon on the same host</description>
  <mitre>
    <id>T1110.001</id>
    <id>T1087.002</id>
  </mitre>
  <group>attack,correlation,</group>
</rule>
```

## Mapowanie MITRE ATT&CK

- `T1087.002`
- `T1110.001`

## Oczekiwany alert

- `100297`, level 13 — eskalacja, z nazwą hosta w treści alertu.

## Co zmieniono i dlaczego

Poprzednia wersja łączyła `100110` (brute force **SSH**, Linux) z `100250`
(rozpoznanie, **Windows**) **bez żadnego klucza korelacji**. Miało to dwie wady
naraz:

1. **Brak klucza** — oba zdarzenia mogły pochodzić z różnych hostów i adresów.
   Brute force SSH na serwer Wazuha i niezwiązane `whoami /groups` na stacji
   roboczej w tych samych 30 minutach wyzwalały alert level 13.
2. **Niespójność źródeł** — SSH (Linux) i Sysmon (Windows) nie mają wspólnego
   pola, więc nie istniał identyfikator, po którym dałoby się je powiązać.
   Dodanie `same_source_ip` nic by nie dało: zdarzenie Sysmona nie niesie
   `srcip` napastnika z sesji SSH.

Naprawa trzyma łańcuch w obrębie jednego systemu — brute force RDP/SMB na
hoście Windows, a następnie rozpoznanie na **tym samym** hoście — i wiąże je
polem `agent.name`, którego oba zdarzenia rzeczywiście używają. To ta sama
konwencja korelacji, co w regule `100299` (C2 na jednym agencie).

## Fałszywe alarmy

Wymóg **tego samego hosta** plus co najmniej dwóch poleceń rozpoznania po
włamaniu znacząco zawęża trafienia względem poprzedniej wersji. Fałszywy alarm
jest wciąż możliwy, gdy administrator prowadzi rozpoznanie na hoście, który
niezależnie był celem brute-force — ale musi to być ten sam host, nie dowolny
w sieci.

## Ograniczenia

- **Nie obejmuje ścieżki SSH.** Włamanie na Linuksa zakończone sukcesem jest
  pokryte osobno regułą `100111` (brute force SSH → udane logowanie z tego
  samego IP). Ta reguła celowo dotyczy tylko hostów Windows.
- **`frequency=2`** — pojedyncze polecenie rozpoznania po włamaniu nie wystarczy.
  Wazuh wymaga `frequency >= 2` dla `if_matched_sid`, a wartość 2 jest tu również
  merytorycznie uzasadniona: napastnik zwykle wykonuje serię poleceń.

## Status weryfikacji

**NOT TESTED / REQUIRES LAB.** Sprawdzone statycznie: poprawność XML, spójność
łańcucha `if_sid`/`if_matched_sid`, obecność pola korelacji, zgodność poziomu
i tagów MITRE z tą dokumentacją. **Nie** sprawdzono, czy reguła faktycznie
wystrzeli — to wymaga działającego managera Wazuh (procedura w
[04-detection-results.md](../04-detection-results.md), sekcja „Jak zmierzyć
to u siebie").

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
