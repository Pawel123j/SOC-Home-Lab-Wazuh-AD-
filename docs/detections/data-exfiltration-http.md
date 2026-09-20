# Eksfiltracja danych przez HTTP

## Technika ataku

Spakowanie zebranych danych do archiwum w katalogu tymczasowym, a następnie
wysłanie go na serwer napastnika serią żądań HTTP.

## Źródło logu

Sysmon EID 11 (`FileCreate`) dla `100232` i EID 3 (`NetworkConnect`) dla `100230`.

## Logika detekcji

Znów kompozycja słabych sygnałów.

`100232` (level 6) odnotowuje utworzenie archiwum w katalogu tymczasowym. Samo
w sobie zdarza się stale i nie zasługuje na uwagę analityka — dlatego level 6,
czyli poniżej progu reagowania.

`100230` (level 10) wykrywa 20+ połączeń tego samego procesu do tego samego adresu
zewnętrznego w 300 s. Negatywny lookahead w wyrażeniu wyklucza adresację wewnętrzną
(`192.168.20.`, `192.168.10.`, `10.`, `127.`, `169.254.`), więc normalna komunikacja
wewnątrz laboratorium nie generuje alertów.

`100231` (level 12) składa oba w jeden sygnał: *spakowano dane, a zaraz potem
wysłano je na zewnątrz*. Dopasowuje grupę `exfil_indicator`, więc kolejne wskaźniki
eksfiltracji wystarczy oznaczyć tą grupą.

## Reguła Wazuh

```xml
<rule id="100232" level="6">
  <if_sid>61613</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\\\(Temp|Windows\\Temp|Public|AppData\\Local\\Temp)\\\\[^\\]+\.(zip|rar|7z|tar\.gz|tgz)$</field>
  <description>Archive file created in temp folder: $(win.eventdata.targetFilename) by $(win.eventdata.image)</description>
  <mitre>
    <id>T1560.001</id>
  </mitre>
  <group>collection,sysmon,exfil_indicator,</group>
</rule>

<rule id="100230" level="10" frequency="20" timeframe="300">
  <if_matched_sid>61605</if_matched_sid>
  <same_field>win.eventdata.image</same_field>
  <same_field>win.eventdata.destinationIp</same_field>
  <field name="win.eventdata.destinationIp" type="pcre2">^(?!192\.168\.20\.|127\.|10\.|169\.254\.|192\.168\.10\.)</field>
  <description>Possible data exfiltration: $(win.eventdata.image) made 20+ connections to $(win.eventdata.destinationIp) in 5 min</description>
  <mitre>
    <id>T1041</id>
    <id>T1030</id>
  </mitre>
  <group>exfiltration,sysmon,attack,exfil_indicator,</group>
</rule>

<rule id="100231" level="12" frequency="2" timeframe="600">
  <if_matched_group>exfil_indicator</if_matched_group>
  <same_field>agent.name</same_field>
  <description>Suspicious archive creation followed by external connection on $(agent.name): possible data exfiltration</description>
  <mitre>
    <id>T1041</id>
    <id>T1560.001</id>
  </mitre>
  <group>attack,exfiltration,correlation,</group>
</rule>
```

## Mapowanie MITRE ATT&CK

- `T1030`
- `T1041`
- `T1560.001`

## Oczekiwany alert

- `100232`, level 6 — poniżej progu triage, widoczne tylko w wyszukiwaniu.
- `100230`, level 10 — triage.
- `100231`, level 12 — alert operacyjny, od którego zaczyna się zgłoszenie.

## Fałszywe alarmy

- **Kopie zapasowe i synchronizacja chmurowa** tworzą archiwa i wysyłają je
  na zewnątrz — czyli dokładnie wzorzec `100231`. To najpoważniejsze źródło
  fałszywych alarmów i w środowisku z OneDrive/Dropbox reguła wymaga wykluczeń
  po `image`.
- **Aktualizacje oprogramowania** potrafią wygenerować serię połączeń
  przekraczającą próg `100230`.

## Ograniczenia

Reguła łapie naiwny wariant „spakuj i wyślij przez HTTP". **Nie wykryje**:

| Technika | Dlaczego nie |
|---|---|
| Eksfiltracja przez DNS | Dane w zapytaniach DNS; wymaga analizy entropii i długości nazw |
| Wysyłka do usług chmurowych | Ruch idzie do legalnych adresów; wymaga inspekcji TLS albo DLP |
| Transfer powolny | Rozłożenie na dni omija okno 300 s |
| Steganografia | Praktycznie niewykrywalne bez analizy behawioralnej |

Pierwsze dwie pozycje są w roadmapie.

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
