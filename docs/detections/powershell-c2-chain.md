# Łańcuch PowerShell C2 (korelacja trzech wskaźników)

## Technika ataku

Uruchomienie stagera frameworka C2 (np. Empire) przez PowerShell: zakodowane
polecenie, pobranie i wykonanie ładunku w pamięci, a następnie regularna
komunikacja z serwerem sterującym.

## Źródło logu

Sysmon EID 1 (`ProcessCreate`) dla `100212`, EID 3 (`NetworkConnect`) dla `100213`,
oraz PowerShell ScriptBlock Logging (EID 4104) dla `100214`. Ostatnie wymaga
włączenia zasady grupy — bez niego `100214` nie ma z czego powstać.

## Logika detekcji

Trzy słabe wskaźniki i jedna reguła, która składa je w mocny sygnał.

Każdy ze wskaźników z osobna jest podatny na fałszywe alarmy: administratorzy
używają zakodowanych poleceń, skrypty instalacyjne pobierają pliki, narzędzia
firmowe łączą się na zewnątrz. Dopiero **trzy wskaźniki w ciągu 60 s na jednym
hoście** tworzą wzorzec, którego nie tłumaczy legalna praca.

Próg 200 znaków base64 w `100212` nie jest przypadkowy: krótkie zakodowane
polecenia są w administracji normalne, a stager frameworka C2 to zwykle kilkaset
znaków i więcej.

`100299` dopasowuje `if_matched_group ps_c2_indicator`, a nie listę identyfikatorów.
To decyzja projektowa: dodanie czwartego wskaźnika wystarczy oznaczyć tą grupą,
a korelacja obejmie go bez zmiany reguły nadrzędnej. Detekcja jako kod, a nie
lista do ręcznego utrzymania.

## Reguła Wazuh

```xml
<rule id="100212" level="11">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\\\powershell(_ise)?\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)-(Enc|EncodedCommand|e )\s+[A-Za-z0-9+/=]{200,}</field>
  <description>Suspicious PowerShell with long EncodedCommand: possible payload obfuscation</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1027</id>
  </mitre>
  <group>execution,defense_evasion,powershell,sysmon,ps_c2_indicator,</group>
</rule>

<rule id="100213" level="10">
  <if_sid>61605</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\\\powershell(_ise)?\.exe$</field>
  <field name="win.eventdata.destinationIp" type="pcre2">^(?!192\.168\.20\.|127\.|10\.|169\.254\.|192\.168\.10\.)</field>
  <description>PowerShell network connection to non-internal IP $(win.eventdata.destinationIp):$(win.eventdata.destinationPort)</description>
  <mitre>
    <id>T1071.001</id>
    <id>T1059.001</id>
  </mitre>
  <group>command_and_control,powershell,sysmon,ps_c2_indicator,</group>
</rule>

<rule id="100214" level="12">
  <if_sid>91802</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(IEX|Invoke-Expression)[^;]*(DownloadString|DownloadData|Invoke-WebRequest|Net\.WebClient)</field>
  <description>PowerShell ScriptBlock with IEX + Download pattern: likely staged payload execution</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1105</id>
  </mitre>
  <group>execution,defense_evasion,powershell,ps_c2_indicator,</group>
</rule>

<rule id="100299" level="14" frequency="3" timeframe="60">
  <if_matched_group>ps_c2_indicator</if_matched_group>
  <same_field>agent.name</same_field>
  <description>Multi-stage PowerShell C2 detected on $(agent.name): 3+ indicators (encoded / IEX-Download / external conn) within 60s</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1071.001</id>
    <id>T1027</id>
  </mitre>
  <group>attack,powershell,correlation,</group>
</rule>
```

## Mapowanie MITRE ATT&CK

- `T1027`
- `T1059.001`
- `T1071.001`
- `T1105`

## Oczekiwany alert

- `100212` level 11, `100213` level 10, `100214` level 12 — pojedynczo, w miarę
  postępu łańcucha.
- `100299` level 14 — meta-alert po trzecim wskaźniku w oknie 60 s. To alert,
  który uzasadnia wybudzenie analityka.

## Fałszywe alarmy

- `100212`: skrypty Windows Update i narzędzia zarządzania konfiguracją
  regularnie używają `-EncodedCommand`. Strojenie przez wykluczenie po
  `parentImage`.
- `100213`: każde legalne narzędzie w PowerShellu sięgające po zasób zewnętrzny
  (moduły z PSGallery, pobieranie aktualizacji).
- `100214`: instalatory oparte na `IEX (New-Object Net.WebClient).DownloadString`
  — wzorzec popularny w skryptach instalacyjnych, w tym legalnych.
- `100299` powinna być odporniejsza, bo wymaga współwystąpienia. **Nie zostało
  to zmierzone** — żeby to wykazać, trzeba uruchomić laboratorium i policzyć
  trafienia; procedura w [04-detection-results.md](../04-detection-results.md).

## Ograniczenia

Napastnik świadomy tej detekcji rozciągnie łańcuch w czasie — trzy wskaźniki
rozłożone na 10 minut ominą okno 60 s. Wydłużenie okna zwiększa jednak liczbę
przypadkowych współwystąpień. Właściwym rozwiązaniem jest okno zmienne albo
punktacja ryzyka per host zamiast twardego progu — kandydat do roadmapy.

Reguła `100213` opiera się na liście prefiksów sieci wewnętrznych wpisanej
w wyrażenie regularne. Zmiana adresacji wymaga edycji reguły — to dług, który
w produkcji rozwiązuje się listą CDB zamiast wyrażeniem.

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
