# Korelacja: brute force poprzedzający rozpoznanie

## Technika ataku

Wzorzec przejętego konta: najpierw udany atak na hasło, potem rozpoznanie
środowiska z wnętrza sieci.

## Źródło logu

Pochodna — reguła nadbudowuje alerty `100110` i `100250`.

## Logika detekcji

`100297` strzela, gdy w oknie 1800 s po alercie `100110` (brute force SSH)
pojawi się alert `100250` (polecenia rozpoznania). Sama w sobie nie analizuje
żadnego surowego zdarzenia — działa wyłącznie na wyjściu innych reguł.

Intencja jest słuszna: rozpoznanie tuż po ataku na hasło to inny sygnał niż
rozpoznanie wykonane przez administratora w środku dnia pracy.

## Reguła Wazuh

```xml
<rule id="100297" level="13" frequency="2" timeframe="1800">
  <if_sid>100250</if_sid>
  <if_matched_sid>100110</if_matched_sid>
  <description>Likely account compromise on $(agent.name): brute force followed by recon activity</description>
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

## Fałszywe alarmy

Przy obecnej konstrukcji fałszywy alarm jest **prawdopodobny**, a nie tylko możliwy —
patrz sekcja poniżej.

## Ograniczenia

**Ta reguła ma znaną słabość i warto ją znać przed pokazaniem jej komukolwiek.**

`100297` nie zawiera `same_source_ip` ani `same_field`, więc oba zdarzenia mogą
pochodzić z **różnych hostów i różnych adresów**. Brute force SSH na serwer Wazuha
i niezwiązane z nim `whoami /groups` wykonane przez administratora na stacji
roboczej w ciągu tych samych 30 minut wyzwolą alert level 13.

Dochodzi do tego niespójność źródeł: `100110` dotyczy SSH (Linux), a `100250`
opiera się na Sysmonie (Windows). Korelacja łączy więc zdarzenia z dwóch różnych
systemów operacyjnych bez żadnego wspólnego identyfikatora — ani konta,
ani adresu, ani hosta.

Poprawa wymaga wspólnego klucza korelacji. Najbliższy sensowny wariant to
powiązanie `100111` (brute force **zakończony sukcesem**) z aktywnością tego
samego konta, zamiast `100110` z dowolnym rozpoznaniem. Wymaga to jednak
normalizacji nazwy konta między światem SSH a Windows, czego obecne laboratorium
nie robi. Pozycja w roadmapie — świadomie nieudawana jako działająca.

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
