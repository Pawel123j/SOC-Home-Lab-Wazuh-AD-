# Brute force na Windows (RDP / SMB)

## Technika ataku

Atak słownikowy na konta domenowe przez RDP albo SMB. `logonType` 3 to logowanie
sieciowe (SMB), 10 to RemoteInteractive (RDP).

## Źródło logu

Dziennik Security kontrolera domeny i stacji roboczej, zdarzenie 4625
(nieudane logowanie). Reguła wbudowana Wazuha: `60122`.

## Logika detekcji

Zliczanie nieudanych logowań per źródłowy adres IP (`same_field win.eventdata.ipAddress`)
z filtrem na typ logowania. Filtr jest istotny: bez niego reguła łapałaby także
`logonType` 2 (logowanie lokalne przy konsoli), gdzie seria pomyłek to zwykle
użytkownik po urlopie, a nie atak.

## Reguła Wazuh

```xml
<rule id="100120" level="11" frequency="10" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <field name="win.eventdata.logonType" type="pcre2">^(3|10)$</field>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>Windows brute force (RDP/SMB): 10 failed logons in 120s from $(win.eventdata.ipAddress) targeting $(win.eventdata.targetUserName)</description>
  <mitre>
    <id>T1110.001</id>
    <id>T1021.001</id>
  </mitre>
  <group>authentication_failed,windows,attack,</group>
</rule>
```

## Mapowanie MITRE ATT&CK

- `T1021.001`
- `T1110.001`

## Oczekiwany alert

- `100120`, level 11 — po dziesiątym nieudanym logowaniu z jednego adresu w 120 s.

## Fałszywe alarmy

- **Konta serwisowe po zmianie hasła.** Najczęstsza przyczyna fałszywych alarmów
  w środowisku domenowym: usługa z zapisanym starym hasłem próbuje logować się
  w pętli, generując dziesiątki 4625 na minutę. Rozpoznanie po `targetUserName`
  wskazującym konto serwisowe i po stałym, regularnym tempie prób.
- **Zmapowane dyski sieciowe** ze starymi poświadczeniami zachowują się tak samo.
- **Zablokowane konto** generuje serię przed zadziałaniem polityki blokady.

## Ograniczenia

Reguła nie wykryje ataku typu *password spraying*, czyli jednego hasła próbowanego
na wielu kontach — tam liczba prób na konto jest niska i celowo mieści się poniżej
progu blokady. Wykrycie wymaga odwrotnego zliczania: wielu różnych `targetUserName`
z jednego źródła. Kandydat do roadmapy.

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
