# Brute force SSH zakończony udanym logowaniem

## Technika ataku

Napastnik z segmentu zewnętrznego (VLAN 30) prowadzi atak słownikowy na usługę SSH
serwera Wazuh. Interesuje nas nie sam atak, lecz moment, w którym się powiedzie.

## Źródło logu

Dziennik `sshd` zbierany przez agenta Wazuha na serwerze (`/var/log/auth.log`).
Reguły wbudowane: `5710` (nieudane logowanie), `5715` (udane logowanie).

## Logika detekcji

Dwustopniowa. `100110` zlicza nieudane próby per źródłowy adres — `same_source_ip`
sprawia, że osiem prób z ośmiu różnych adresów nie wyzwoli reguły, a osiem z jednego
już tak. `100111` nadbudowuje to: strzela wtedy, gdy w ciągu 600 s po serii
pojawi się **udane** logowanie z tego samego adresu.

Ten podział jest sednem scenariusza. Nieudane logowania SSH to szum — każdy host
wystawiony do sieci widzi ich setki dziennie i reagowanie na nie jest stratą czasu
analityka. Sygnałem operacyjnym jest przejście od „ktoś puka" do „ktoś wszedł",
i tylko ono dostaje level 14.

## Reguła Wazuh

```xml
<rule id="100110" level="12" frequency="8" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <srcip>192.168.30.0/24</srcip>
  <description>SSH brute force from external segment (VLAN 30): 8 failed attempts in 120s from $(srcip)</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
  <group>authentication_failed,attack,pci_dss_10.2.4,pci_dss_10.2.5,gpg13_7.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,</group>
</rule>

<rule id="100111" level="14" frequency="2" timeframe="600">
  <if_sid>5715</if_sid>
  <if_matched_sid>100110</if_matched_sid>
  <same_source_ip />
  <description>SSH successful login from $(srcip) preceded by brute force: likely compromised account</description>
  <mitre>
    <id>T1110.001</id>
    <id>T1078</id>
  </mitre>
  <group>authentication_success,attack,</group>
</rule>
```

## Mapowanie MITRE ATT&CK

- `T1078`
- `T1110.001`

## Oczekiwany alert

- `100110`, level 12 — po ósmej nieudanej próbie w oknie 120 s.
- `100111`, level 14 — jeżeli w ciągu kolejnych 600 s to samo IP zaloguje się skutecznie.
  Ten alert oznacza przejęte konto i wymaga natychmiastowej reakcji.

## Fałszywe alarmy

- **Skanery podatności i monitoring.** Sonda sprawdzająca dostępność SSH generuje
  serie nieudanych logowań z jednego adresu — czyli dokładnie wzorzec `100110`.
  Strojenie: wykluczenie adresów skanerów.
- **Klient z nieaktualnym kluczem.** Automat z przeterminowanym kluczem potrafi
  wygenerować serię prób przy każdej próbie połączenia.
- `100111` jest wyraźnie mniej podatna na fałszywe alarmy niż `100110`: wymaga
  korelacji z sukcesem, a skaner zwykle się nie loguje.

## Ograniczenia

Ograniczenie `<srcip>192.168.30.0/24</srcip>` zawęża `100110` do segmentu napastnika.
W laboratorium redukuje to szum, ale **w produkcji byłby to błąd** — brute force
z wewnątrz sieci nie zostałby wykryty. Przy przenoszeniu reguły dalej to ograniczenie
trzeba usunąć i zastąpić listą wykluczeń dla znanych skanerów.

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
