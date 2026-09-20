# Dostęp do pamięci LSASS (zrzut poświadczeń)

## Technika ataku

Odczyt pamięci procesu `lsass.exe` w celu wydobycia poświadczeń — technika
stosowana przez Mimikatza i jego pochodne, a także przez wariant LOLBAS
wykorzystujący `comsvcs.dll`.

## Źródło logu

Sysmon EID 10 (`ProcessAccess`) dla `100210` oraz EID 1 (`ProcessCreate`)
dla `100211`. **Bez Sysmona ta detekcja nie istnieje** — sam dziennik Security
Windows nie raportuje otwarcia uchwytu do procesu.

## Logika detekcji

`100210` nie szuka nazwy narzędzia, tylko maski uprawnień, o którą proces poprosił,
otwierając uchwyt do LSASS:

| Maska | Znaczenie |
|---|---|
| `0x1410` | `PROCESS_QUERY_LIMITED_INFORMATION` + `PROCESS_VM_READ` — minimum potrzebne do odczytu pamięci |
| `0x1010` | wariant z samym odczytem pamięci |
| `0x1438`, `0x143a` | warianty obserwowane dla narzędzi zrzucających pamięć |
| `0x1fffff` | `PROCESS_ALL_ACCESS` — pełny dostęp |

Zmiana nazwy pliku wykonywalnego to kwestia sekundy; sposobu odczytania pamięci
procesu zmienić się nie da. To różnica między detekcją opartą na sygnaturze
a detekcją opartą na technice — i powód, dla którego ta reguła przetrwa podmianę
narzędzia.

`100211` łapie wariant bez własnego binarium: `rundll32` wywołujący eksport
`MiniDump` z `comsvcs.dll`, czyli zrzut pamięci przy użyciu komponentu systemowego.

## Reguła Wazuh

```xml
<rule id="100210" level="14">
  <if_sid>61609</if_sid>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)\\\\lsass\.exe$</field>
  <field name="win.eventdata.grantedAccess" type="pcre2">(?i)0x(1010|1410|1438|143a|1fffff)</field>
  <description>Possible LSASS memory access (Mimikatz-like): $(win.eventdata.sourceImage) accessed lsass.exe with GrantedAccess=$(win.eventdata.grantedAccess)</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_access,sysmon,attack,</group>
</rule>

<rule id="100211" level="13">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)rundll32.*comsvcs(\.dll)?.*MiniDump</field>
  <description>LSASS dump via comsvcs.dll (LOLBAS): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1003.001</id>
    <id>T1218.011</id>
  </mitre>
  <group>credential_access,defense_evasion,sysmon,lolbas,attack,</group>
</rule>
```

## Mapowanie MITRE ATT&CK

- `T1003.001`
- `T1218.011`

## Oczekiwany alert

- `100210`, level 14 — alert z `sourceImage` wskazującym proces, który sięgnął po LSASS.
- `100211`, level 13 — pełna linia poleceń `rundll32` w treści alertu.

Oba poziomy oznaczają natychmiastową eskalację: udany zrzut LSASS to poświadczenia
w rękach napastnika i konieczność rotacji haseł.

## Fałszywe alarmy

**To reguła z realnym ryzykiem fałszywych alarmów** i trzeba to powiedzieć wprost.

- **Produkty EDR i antywirusowe** (Defender for Endpoint, CrowdStrike) czytają
  pamięć LSASS w ramach skanowania i **będą** wyzwalać `100210`.
- **Narzędzia diagnostyczne** (`procdump`, Menedżer zadań przy tworzeniu zrzutu)
  robią dokładnie to samo, co narzędzie ofensywne.

Strojenie polega na wykluczeniu po `win.eventdata.sourceImage` — po ustaleniu,
które procesy w danym środowisku robią to legalnie. **Wykluczać należy pełną
ścieżkę, nie samą nazwę pliku**: nazwę da się podszyć, umieszczając własny plik
o nazwie zaufanego procesu w innym katalogu.

## Ograniczenia

Reguła nie wykryje odczytu pamięci LSASS z poziomu jądra ani technik, które
omijają `OpenProcess` (np. wykorzystanie istniejącego uchwytu przejętego od innego
procesu). Nie wykryje też zrzutu wykonanego na kopii pamięci utworzonej wcześniej
innym sposobem.

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
