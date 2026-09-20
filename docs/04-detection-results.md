# 04 — Oczekiwane detekcje

Dokument opisuje, **co powinno wystrzelić** przy scenariuszach z
[03-attack-scenarios.md](03-attack-scenarios.md) i **dlaczego** — wprost z
definicji reguł w [`detection-rules/custom-wazuh-rules.xml`](../detection-rules/custom-wazuh-rules.xml).

> ### Status walidacji
>
> **To nie jest zapis przebiegu laboratorium.** Każdy próg, poziom alertu
> i tag MITRE poniżej wynika z definicji reguły w repozytorium i można go
> sprawdzić, czytając XML — ale **żaden licznik trafień ani wskaźnik
> TP/FP nie pochodzi z wykonanego ataku.**
>
> Laboratorium wymaga trzech maszyn wirtualnych (Windows Server z AD,
> stacja robocza z Sysmonem, Wazuh Server) i nie da się go odtworzyć
> w CI. Sekcja [Jak zmierzyć to u siebie](#jak-zmierzyć-to-u-siebie)
> zawiera procedurę i pustą tabelę do wypełnienia własnymi wynikami.
>
> Co **jest** zweryfikowane automatycznie: składnia reguł, unikalność
> identyfikatorów, poprawność tagów MITRE i zgodność reguł Sigma —
> workflow `Walidacja detekcji` uruchamiany przy każdym pushu.

---

## Konwencja oznaczeń

- **Poziom alertu (level):** skala Wazuh 0–15. W praktyce SOC: < 7 ignorujemy,
  7–9 interesujące, 10–12 triage, 13–15 natychmiastowa eskalacja.
- **Rule ID:** `100xxx` to reguły własne z tego repozytorium; `< 10000` to
  wbudowane reguły Wazuha, na których się opieramy przez `if_sid`.
- **MITRE:** każda reguła ma tagowanie w `rule.mitre.id`, co pozwala filtrować
  dashboard po technice.

---

## Scenariusz 1 — Brute force SSH

### Co ma wystrzelić

| Reguła | Poziom | Warunek wyzwolenia | MITRE |
|---|---|---|---|
| `5710` (wbudowana) | 5 | pojedyncza nieudana próba SSH | — |
| **`100110`** | **12** | **8 nieudanych prób w 120 s z tego samego IP w zakresie `192.168.30.0/24`** | T1110.001 |
| **`100111`** | **14** | **udane logowanie w 600 s po serii z `100110`** | T1110.001, T1078 |

`100110` używa `<if_matched_sid>5710</if_matched_sid>` z `<same_source_ip />`,
więc liczy próby per źródłowy adres, nie globalnie. Ograniczenie
`<srcip>192.168.30.0/24</srcip>` zawęża regułę do segmentu napastnika (VLAN 30) —
w laboratorium to redukuje szum, ale w produkcji byłoby błędem, bo atak
z wewnątrz nie zostałby złapany. Świadomy kompromis, opisany tutaj, żeby nie
przeniósł się nieświadomie dalej.

### Co jest tu wartościowe

Para `100110` → `100111` jest ciekawsza niż sam brute force. Nieudane próby to
szum — codziennie widać je na każdym hoście wystawionym do internetu. Sygnałem
jest **brute force zakończony sukcesem**: `100111` odpala tylko wtedy, gdy po
serii nieudanych prób pojawi się udane logowanie z tego samego adresu. To
przejście z „ktoś puka" do „ktoś wszedł", i dlatego dostaje level 14.

### False positives, których się spodziewam

- Skanery podatności i monitoring (np. sonda sprawdzająca dostępność SSH)
  generują serie nieudanych logowań. Wykluczenie po `srcip`.
- Źle skonfigurowany klient z nieaktualnym kluczem potrafi wygenerować
  serię prób przy każdej próbie połączenia.

---

## Scenariusz 2 — Dostęp do pamięci LSASS

### Co ma wystrzelić

| Reguła | Poziom | Warunek wyzwolenia | MITRE |
|---|---|---|---|
| **`100210`** | **14** | Sysmon EID 10, `targetImage` kończy się na `\lsass.exe`, `grantedAccess` ∈ {`0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`} | T1003.001 |
| **`100211`** | **13** | linia poleceń zawierająca wywołanie `comsvcs.dll MiniDump` | T1003.001, T1218.011 |

### Dlaczego akurat te maski dostępu

To sedno tej reguły. `grantedAccess` mówi, **o jakie uprawnienia** proces
poprosił, otwierając uchwyt do LSASS:

- `0x1410` = `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` — minimalny
  zestaw potrzebny do odczytania pamięci procesu, czyli dokładnie to, czego
  wymaga zrzut poświadczeń.
- `0x1fffff` = `PROCESS_ALL_ACCESS` — pełny dostęp.

Reguła nie szuka nazwy `mimikatz.exe`, bo zmiana nazwy pliku to kwestia sekundy.
Szuka **zachowania**, którego nie da się uniknąć, jeśli celem jest odczyt pamięci
LSASS. To różnica między detekcją opartą na sygnaturze a detekcją opartą na
technice — i powód, dla którego reguła przetrwa zmianę narzędzia.

Warunek `if_sid 61609` oznacza, że reguła nadbudowuje wbudowaną regułę Wazuha
dla Sysmon EID 10 — bez Sysmona ta detekcja nie istnieje, sam dziennik
Security Windows nie daje wglądu w `ProcessAccess`.

### False positives, których się spodziewam

To reguła z realnym ryzykiem fałszywych alarmów. Produkty EDR i antywirusowe
(Defender for Endpoint, CrowdStrike) czytają pamięć LSASS w ramach skanowania
i **będą** wyzwalać tę regułę. Strojenie polega na wykluczeniu po
`win.eventdata.sourceImage` — po ustaleniu, które konkretnie procesy w danym
środowisku robią to legalnie. Wykluczać należy pełną ścieżkę, nie samą nazwę
pliku, bo nazwę da się podszyć.

---

## Scenariusz 3 — Łańcuch PowerShell C2

Tu widać, po co w ogóle korelacja.

### Reguły składowe

| Reguła | Poziom | Warunek wyzwolenia | MITRE |
|---|---|---|---|
| `100212` | 11 | `powershell.exe` z `-Enc`/`-EncodedCommand` i ciągiem base64 **≥ 200 znaków** | T1059.001, T1027 |
| `100213` | 10 | połączenie sieciowe PowerShella do adresu spoza sieci wewnętrznej | T1071.001, T1059.001 |
| `100214` | 12 | `scriptBlockText` zawiera `IEX`/`Invoke-Expression` razem z `DownloadString`/`Net.WebClient` | T1059.001, T1105 |

Wszystkie trzy należą do grupy `ps_c2_indicator`.

### Reguła korelacyjna

| Reguła | Poziom | Warunek wyzwolenia | MITRE |
|---|---|---|---|
| **`100299`** | **14** | **3 zdarzenia z grupy `ps_c2_indicator` w 60 s na tym samym `agent.name`** | T1059.001, T1071.001, T1027 |

`100299` nie wymienia reguł składowych po identyfikatorach — dopasowuje
`if_matched_group ps_c2_indicator`. To celowe: dodanie czwartego wskaźnika
PowerShellowego wystarczy oznaczyć tą grupą, a korelacja obejmie go bez zmiany
reguły nadrzędnej. Detekcja jako kod, a nie lista identyfikatorów do ręcznego
utrzymania.

### Dlaczego to podejście ma sens

Każda reguła składowa z osobna jest podatna na fałszywe alarmy — administratorzy
używają zakodowanych poleceń, skrypty instalacyjne pobierają pliki, narzędzia
firmowe łączą się na zewnątrz. Dopiero **współwystąpienie trzech wskaźników
w minucie na jednym hoście** jest wzorcem, który trudno wytłumaczyć legalną
pracą.

Próg 200 znaków base64 w `100212` też nie jest przypadkowy: krótkie zakodowane
polecenia są w administracji normalne, a stager frameworka C2 to zwykle kilkaset
znaków i więcej.

**Uczciwe zastrzeżenie:** że ta konstrukcja *powinna* dawać mniej fałszywych
alarmów niż reguły składowe, wynika z jej logiki — ale **nie zmierzyłem tego**.
Żeby to wykazać, trzeba puścić laboratorium i policzyć trafienia; tabela
w ostatniej sekcji jest na to przygotowana.

---

## Scenariusz 4 — `mshta` jako proxy wykonania

| Reguła | Poziom | Warunek wyzwolenia | MITRE |
|---|---|---|---|
| `100220` | 12 | `mshta.exe` z adresem URL w linii poleceń | T1218.005 |
| **`100221`** | **13** | **`parentImage` = `mshta.exe`, a `image` ∈ {`powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`}** | T1218.005, T1059 |

`100221` opiera się na relacji rodzic–dziecko, nie na samym uruchomieniu
`mshta`. Powód: `mshta.exe` uruchamiający interpreter poleceń nie ma
praktycznie zastosowań w nowoczesnym środowisku Windows. Aplikacje HTA były
normalne kilkanaście lat temu; dziś ten łańcuch procesów to niemal zawsze
technika omijania kontroli aplikacji.

Level 13, a nie 15 — 15 rezerwujemy na potwierdzone niszczenie danych
i ransomware.

---

## Scenariusz 5 — Eksfiltracja przez HTTP

| Reguła | Poziom | Warunek wyzwolenia | MITRE |
|---|---|---|---|
| `100232` | 6 | utworzenie pliku archiwum w katalogu tymczasowym | T1560.001 |
| `100230` | 10 | **20+ połączeń** tego samego procesu do tego samego adresu zewnętrznego w **300 s** | T1041, T1030 |
| **`100231`** | **12** | **2 zdarzenia z grupy `exfil_indicator` w 600 s na tym samym hoście** | T1041, T1560.001 |

Wyrażenie w `100230` wyklucza adresy wewnętrzne przez negatywny lookahead
(`192.168.20.`, `192.168.10.`, `10.`, `127.`, `169.254.`), więc regularna
komunikacja z serwerami laboratorium nie generuje alertów.

`100231` łączy dwa słabe sygnały — samo utworzenie archiwum w `%TEMP%` (level 6,
zdarza się stale) i sam ruch wychodzący — w jeden mocny: *spakowano dane,
a zaraz potem wysłano je na zewnątrz*.

### Granice tej detekcji

Reguła łapie naiwny wariant „spakuj i wyślij przez HTTP". Nie wykryje:

- **eksfiltracji przez DNS** — wymaga osobnej analizy statystyk zapytań,
- **wysyłki do usług chmurowych** (Dropbox, S3, Mega) — ruch idzie do legalnych
  adresów, potrzebna inspekcja TLS albo DLP,
- **transferu powolnego** — rozłożenie na dni omija okno 300 s,
- **steganografii** — praktycznie niewykrywalne bez analizy behawioralnej.

Pierwsze dwa punkty są w [ROADMAP](#roadmap-detekcji) jako kandydaci na kolejne
reguły.

---

## Jak zmierzyć to u siebie

Żeby zamienić ten dokument w zapis rzeczywistych wyników:

1. Postaw laboratorium według [02-installation.md](02-installation.md)
   (3 maszyny wirtualne, Vagrant + Ansible).
2. Odczekaj co najmniej dobę z włączonym Sysmonem **bez wykonywania ataków** —
   to daje bazę fałszywych alarmów z normalnej pracy. Bez tego kroku wskaźnik
   TP/FP nie ma sensu.
3. Wykonaj scenariusze z [03-attack-scenarios.md](03-attack-scenarios.md),
   notując czas rozpoczęcia i zakończenia każdego.
4. Zbierz trafienia per reguła:

   ```bash
   sudo jq -r 'select(.rule.id | test("^100[0-9]{3}$")) | .rule.id' \
       /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn
   ```

5. Zaklasyfikuj każde trafienie jako prawdziwie dodatnie albo fałszywie dodatnie,
   porównując znacznik czasu z notatkami z punktu 3.
6. Wypełnij tabelę i **zamień ten akapit na datę oraz czas trwania pomiaru**.

| Rule ID | Opis | Trafienia | TP | FP | Uwagi do strojenia |
|---|---|---|---|---|---|
| 100110 | Brute force SSH z segmentu zewnętrznego | | | | |
| 100111 | Brute force zakończony udanym logowaniem | | | | |
| 100120 | Brute force Windows (RDP/SMB) | | | | |
| 100210 | Dostęp do pamięci LSASS | | | | |
| 100211 | Zrzut LSASS przez `comsvcs.dll` | | | | |
| 100212 | PowerShell: długi `EncodedCommand` | | | | |
| 100213 | PowerShell: połączenie zewnętrzne | | | | |
| 100214 | PowerShell: `IEX` + pobranie | | | | |
| 100220 | `mshta` z adresem URL | | | | |
| 100221 | `mshta` uruchamia interpreter | | | | |
| 100230 | Wiele połączeń zewnętrznych | | | | |
| 100231 | Archiwum + ruch wychodzący | | | | |
| 100232 | Archiwum w katalogu tymczasowym | | | | |
| 100240 | Utrwalenie w kluczu `Run` | | | | |
| 100250 | Polecenia rozpoznania | | | | |
| 100297 | Korelacja: brute force + rozpoznanie | | | | |
| 100299 | Korelacja: łańcuch PowerShell C2 | | | | |

Zrzuty ekranu z dashboardu: instrukcja w
[docs/screenshots/README.md](screenshots/README.md).

---

## Decyzje projektowe

To wnioski z **projektowania** tych reguł, nie z pomiaru:

1. **Detekcja po technice, nie po nazwie narzędzia.** `100210` szuka maski
   dostępu do LSASS, a nie ciągu `mimikatz`. Nazwę pliku zmienia się w sekundę;
   sposobu odczytania pamięci procesu — nie.

2. **Korelacja tam, gdzie pojedynczy sygnał jest za słaby.** `100299` i `100231`
   istnieją dlatego, że ich składowe same w sobie generowałyby zbyt wiele
   fałszywych alarmów, żeby na nie reagować.

3. **Grupy zamiast list identyfikatorów.** Reguły korelacyjne dopasowują
   `if_matched_group`, więc rozszerzenie zestawu wskaźników nie wymaga zmiany
   reguły nadrzędnej.

4. **Sysmon jest warunkiem koniecznym.** Bez EID 10 (`ProcessAccess`) reguła
   `100210` nie ma z czego powstać — sam dziennik Security Windows nie daje
   takiej widoczności. To ograniczenie architektury, nie konfiguracji.

5. **Tagowanie MITRE przy każdej regule.** Pozwala odpowiedzieć na pytanie
   „jakie mamy pokrycie dla T1003?" filtrem w dashboardzie, zamiast czytania
   XML-a.

6. **Active Response świadomie nie jest włączony.** Automatyczne blokowanie IP
   przy fałszywym alarmie odcina własnych użytkowników. Gdyby włączać, to tylko
   dla poziomu ≥ 12 i z listą wykluczeń dla adresów administracyjnych — ale to
   decyzja, która wymaga zmierzonego wskaźnika FP, a tego jeszcze nie ma.

---

## Roadmap detekcji

Scenariusze, których **nie da się** obsłużyć obecnym laboratorium bez
dodatkowej infrastruktury:

| Scenariusz | Czego brakuje |
|---|---|
| Eksfiltracja przez DNS | Zbieranie logów zapytań DNS + analiza statystyczna długości i entropii |
| Nadużycie Kerberosa (Kerberoasting, Golden Ticket) | Audyt EID 4769 i polityka logowania biletów na kontrolerze domeny |
| Ruch boczny przez WMI/WinRM | Sysmon EID 19–21 oraz logi WinRM na hostach docelowych |
| Wykrywanie ransomware | Monitorowanie operacji plikowych na dużą skalę, EID 11 na całym wolumenie |
| Eksfiltracja do chmury | Inspekcja TLS albo integracja z proxy/DLP |

---

Dalej: [reports/incident-report-template.md](../reports/incident-report-template.md) —
szablon raportu z obsługi incydentu.
