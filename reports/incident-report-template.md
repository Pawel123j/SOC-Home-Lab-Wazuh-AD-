# Raport z incydentu bezpieczeństwa — IR-YYYY-NNNN

> Szablon zgodny z **NIST SP 800-61 Rev. 2** (Computer Security Incident Handling Guide), uzupełniony o pola wymagane przez kontrolery RODO art. 33 (notyfikacja w 72 h) i typowy workflow SOC tier 2.
>
> **Sposób użycia:** dla każdego incydentu z laboratorium wypełniam ten szablon (po zakończeniu scenariusza). Plik zapisuję jako `IR-YYYY-NNNN-<short-name>.md`, np. `IR-2026-0001-lsass-dump-ws01.md`.

---

## 0. Metadane

| Pole | Wartość |
|---|---|
| **Identyfikator** | `IR-YYYY-NNNN` |
| **Tytuł** | krótki, < 80 znaków, opisuje co się stało |
| **Data utworzenia** | YYYY-MM-DD HH:MM (czas analityka) |
| **Data wykrycia** | YYYY-MM-DD HH:MM (timestamp pierwszego alertu) |
| **Data wystąpienia** | YYYY-MM-DD HH:MM (jeśli różny od wykrycia — szacowanie) |
| **Severity** | low / medium / **high** / critical |
| **Status** | new / triage / containment / eradication / recovery / **closed** |
| **Analityk prowadzący** | imię.nazwisko |
| **Eskalacja do** | tier 2 / tier 3 / CISO / legal / PUODO |
| **Powiązane tickety** | linki do JIRA / ServiceNow |

---

## 1. Streszczenie zarządcze (Executive Summary)

> 3–5 zdań po polsku, dla niesionowego czytelnika. Co się stało, co zrobiliśmy, jakie jest ryzyko biznesowe, jaki status.

**Przykład wypełnienia:**

> W dniu 2026-05-21 o 14:31 system SIEM (Wazuh) wykrył próbę wyciągnięcia poświadczeń (haseł) z pamięci kontrolera domeny dc01.soclab.local. Atakujący posłużył się techniką znaną jako "LSASS dumping" (MITRE T1003.001). Działanie nie zostało potwierdzone jako skuteczne — host został odizolowany w ciągu 4 minut od pierwszego alertu, hasła kont uprzywilejowanych zresetowano profilaktycznie. Brak dowodów na dalszą eskalację. Postępowanie zamknięto jako True Positive — działanie wewnętrznego red-team.

---

## 2. Klasyfikacja MITRE ATT&CK

| Tactic | Technique | Sub-technique | Obserwacja |
|---|---|---|---|
| Credential Access | T1003 | T1003.001 (LSASS Memory) | Sysmon EID 10 z GrantedAccess 0x1410 do lsass.exe na dc01 |
| Defense Evasion | T1218 | T1218.011 (Rundll32) | rundll32.exe + comsvcs.dll, MiniDump |
| _(dodaj kolejne)_ | | | |

---

## 3. Indicators of Compromise (IoC)

### 3.1. Sieciowe

| Typ | Wartość | Pierwsze wystąpienie | Notes |
|---|---|---|---|
| Source IP | 192.168.30.30 | 2026-05-21 14:31:08 | Host Kali w VLAN 30 |
| Destination IP | — | | |
| URL / domain | — | | |
| User-Agent | — | | |

### 3.2. Hostowe

| Typ | Wartość | Hash (SHA256) | Lokalizacja | Notes |
|---|---|---|---|---|
| Process | `dumper.exe` | `a3b...` | `C:\Tools\dumper.exe` | Niepodpisany binarka |
| File | `lsass.dmp` | `7c4...` | `C:\Windows\Temp\lsass.dmp` | Output dumpera |
| Command | `rundll32 comsvcs.dll, MiniDump 624 C:\Windows\Temp\lsass2.dmp full` | n/d | CMD line | LOLBAS |

### 3.3. Konta

| Konto | Domena | Typ aktywności | Status reset |
|---|---|---|---|
| akowalska | SOCLAB | Process create / interactive logon | ✅ Reset 2026-05-21 14:42 |

---

## 4. Timeline (UTC+02)

| Czas | Źródło | Zdarzenie |
|---|---|---|
| 14:30:50 | WS01 — Sysmon EID 11 | Utworzenie pliku `C:\Tools\dumper.exe` przez `cmd.exe` (parent: `explorer.exe`, user: akowalska) |
| 14:31:01 | WS01 — Sysmon EID 1 | Wykonanie `C:\Tools\dumper.exe` |
| 14:31:02 | WS01 — Sysmon EID 10 | `dumper.exe` otwiera `lsass.exe` z GrantedAccess=0x1410 |
| 14:31:02 | Wazuh | **Alert level 14 — rule 100210** ("Possible LSASS memory access") |
| 14:31:03 | WS01 — Sysmon EID 11 | FileCreate: `C:\Windows\Temp\lsass.dmp` (47.2 MB) |
| 14:31:04 | Wazuh | Alert level 6 — rule 100232 (".dmp w Temp") |
| 14:31:11 | SOC analyst | Pierwszy alert przeglądnięty, **status: triage** |
| 14:31:30 | WS01 — Sysmon EID 1 | `cmd.exe /c rundll32 ... comsvcs ... MiniDump 624 ...` |
| 14:31:31 | Wazuh | **Alert level 13 — rule 100211** ("LSASS dump via comsvcs") |
| 14:32:05 | SOC analyst | Eskalacja na tier 2 |
| 14:34:00 | SOC tier 2 | **Containment:** Wazuh Active Response → izolacja WS01 (firewall block) |
| 14:42:11 | SOC tier 2 | Reset haseł kont: akowalska, dc01$, ws01$ |
| 14:55:00 | SOC tier 2 | Pull plików `.dmp` z WS01 do storage forensic |
| 15:20:00 | SOC tier 2 | Triage zakończony, status: **eradication** |
| 16:00:00 | IT Ops | Reimage WS01 z czystego golden image |
| 16:30:00 | SOC tier 2 | Verification: brak follow-up activity. **Status: closed (TP)** |

**Dwell time** (czas między infekcją a wykryciem): **~12 sekund**
**Time to Containment** (czas od wykrycia do izolacji): **~3 minuty**
**Time to Recovery**: **~95 minut**

---

## 5. Wpływ na biznes (Business Impact)

| Pytanie | Odpowiedź |
|---|---|
| Czy doszło do wycieku danych osobowych (RODO)? | NIE (potwierdzone) / TAK / NIE WIADOMO |
| Czy systemy produkcyjne były niedostępne? | NIE / TAK — czas: __ min |
| Czy doszło do utraty integralności danych? | NIE / TAK — opis |
| Czy konieczna jest notyfikacja PUODO? | NIE / TAK — termin: __ |
| Czy konieczna jest notyfikacja klientów? | NIE / TAK |
| Szacowany koszt (godziny pracy + downtime) | __ PLN |

**Uwaga dotycząca RODO art. 33:** jeśli zaznaczono "TAK" dla wycieku danych osobowych, notyfikacja do PUODO musi nastąpić w ciągu **72 godzin** od wykrycia, niezależnie od weekendu.

---

## 6. Analiza techniczna

### 6.1. Wektor wejścia (Initial Access)

> Opisz, jak atakujący się dostał. Phishing? Eksploit? RDP brute? Inside threat?
> Jeśli nieznany — wpisz "nieznany" i wskaż, czego brakuje do ustalenia.

**Przykład:** Atakujący zalogował się na konto `akowalska` przez RDP z hosta 192.168.30.30 (VLAN 30). Hasło konta `akowalska` to "Wiosna2024!" — proste, sezonowe, prawdopodobnie złamane brute-force lub odgadnięte. Brak MFA na koncie domenowym.

### 6.2. Egzekucja (Execution)

> Co konkretnie zostało uruchomione, w jakim kontekście, jakie procesy spawn-owano.

**Przykład:** Atakujący uruchomił `cmd.exe` przez RDP, pobrał `dumper.exe` (transferem RDP clipboard albo `mshta http://...`), wykonał z folderu `C:\Tools\`. Następnie uruchomił wariant LOLBAS przez `rundll32 + comsvcs`.

### 6.3. Persistence / Privilege Escalation / Lateral Movement

> Czy atakujący zostawił sobie tylne drzwi? Eskalował uprawnienia? Próbował się przemieścić?

**Przykład:** Brak persistence (NIE wykryto: nowe usługi, klucze Run, scheduled tasks, modyfikacje GPO). Brak ruchu bocznego — żadnych połączeń wychodzących z WS01 do innych hostów w VLAN 20 poza dc01 (normalna komunikacja AD).

### 6.4. Co atakujący mógł zdobyć

> Realistyczna analiza tego, co BY uzyskał, gdyby się udało.

**Przykład:** Plik `lsass.dmp` (47 MB) zawiera w pamięci NTLM hashe wszystkich kont, które logowały się na WS01 od ostatniego restartu, oraz bilety Kerberos z aktywnych sesji. Konto `akowalska` należy do `Domain Admins` → kompromitacja całej domeny `soclab.local`.

### 6.5. Co realnie wyciekło

> Co zostało rzeczywiście wyniesione. Jeśli plik powstał ale nie został wysłany — odnotuj.

**Przykład:** Plik `lsass.dmp` został utworzony lokalnie na WS01, ale **nie ma dowodu na exfiltrację**. Sysmon EID 3 nie pokazuje połączeń wychodzących z `dumper.exe` ani `rundll32.exe`. Najbardziej prawdopodobny scenariusz: atakujący nie zdążył wyekstrahować pliku przed izolacją hosta.

---

## 7. Działania containment / eradication / recovery

### 7.1. Containment (powstrzymanie)

- [x] **14:34** — Wazuh Active Response → blokada ruchu sieciowego z WS01 (firewall rule)
- [x] **14:42** — reset hasła `akowalska` przez DC01 (`Set-ADAccountPassword`)
- [x] **14:42** — reset password `dc01$`, `ws01$` (machine accounts)
- [x] **14:45** — blokada konta akowalska (`Disable-ADAccount`) do czasu weryfikacji
- [x] **14:50** — RDP zablokowane na WS01 (firewall outbound, `New-NetFirewallRule`)
- [x] **15:00** — `kinit` ticket purge na DC01 (wymuszenie ponownego logowania)

### 7.2. Eradication (usuwanie)

- [x] **16:00** — WS01 zostaje wyłączony, dysk podłączony do stacji forensic
- [x] **16:30** — pełna ekstrakcja artefaktów: pliki `.dmp`, prefetch, NTUSER.DAT, eventlog, Sysmon log, transcripts PowerShell
- [x] **17:00** — wipe i reimage WS01 z golden image (build 2026.05)
- [x] **17:30** — agent Wazuh + Sysmon zainstalowany na świeżym hoście

### 7.3. Recovery (przywrócenie)

- [x] **18:00** — WS01 przywrócony do domeny, user `akowalska` z nowym hasłem
- [x] **18:30** — monitoring wzmożony (custom dashboard `WS01-watch` na 7 dni)
- [x] **2026-05-22** — brak follow-up activity w 24h post-recovery

---

## 8. Lessons Learned

### Co poszło dobrze

1. **MTTD = 12 sekund.** Wazuh wykrył dump LSASS niemal natychmiast — reguła 100210 (custom) okazała się bardzo precyzyjna.
2. **Active Response zadziałał.** Izolacja sieciowa w ciągu 3 min od pierwszego alertu zatrzymała exfil zanim się zaczął.
3. **Sysmon dał pełen kontekst.** Analiza była natychmiastowa, bo mieliśmy EID 1 + 10 + 11 w jednym widoku.

### Co poszło źle

1. **Brak MFA na kontach domenowych.** Atakujący w ogóle nie powinien móc się zalogować po brute-force.
2. **Hasła sezonowe ("Wiosna2024!") na koncie Domain Admin.** Polityka haseł zbyt słaba.
3. **RDP otwarty z segmentu VLAN 30.** Powinien być zamknięty lub dostępny tylko przez jump-host.
4. **Defender wyłączony na WS01.** W labie celowo — w prod absolutnie nie.

### Action items (priorytety)

| # | Akcja | Owner | Deadline | Status |
|---|---|---|---|---|
| 1 | Wymuszenie MFA dla wszystkich kont Domain Admins | IT/AD team | 2026-05-28 | 🟡 in progress |
| 2 | Wprowadzenie LAPS dla lokalnych adminów | IT/AD team | 2026-06-05 | 🟡 in progress |
| 3 | Polityka haseł: min. 14 znaków, brak sezonowych | IT/AD + HR | 2026-05-30 | 🔴 not started |
| 4 | RDP — closed by default, otwierany przez PAM/JIT | Network team | 2026-06-15 | 🔴 not started |
| 5 | Tier 0 lockdown — admini nie logują się interaktywnie na workstacjach | IT/AD team | 2026-06-30 | 🔴 not started |
| 6 | Detekcja: reguła Wazuh na "Domain Admin interactive logon na non-DC" | SOC | 2026-05-25 | 🟢 done |

### Pytania, na które nie umiem odpowiedzieć (do follow-up)

1. Skąd atakujący znał hasło `akowalska`? Czy to brute-force, OSINT (LinkedIn?), czy inside threat?
2. Czy `dumper.exe` to publicznie znana paczka (Mimikatz wariant) czy custom? Hash do analizy w VT/MalwareBazaar.
3. Czy są inne hosty w VLAN 20 z włamaniem? Wymaga hunt-query za ostatnie 30 dni.

---

## 9. Dowody (chain of custody)

> Lista wszystkich artefaktów z hashami SHA256, gdzie są przechowywane i kto miał dostęp.

| Artefakt | SHA256 | Pochodzenie | Lokalizacja | Czas zebrania | Zebrał |
|---|---|---|---|---|---|
| `ws01-lsass.dmp` | `7c4d...` | `C:\Windows\Temp\lsass.dmp` z WS01 | `forensics://ir-2026-0001/` | 2026-05-21 16:35 | jnowak (tier 2) |
| `ws01-sysmon.evtx` | `a91f...` | `C:\Windows\System32\winevt\Logs\` z WS01 | `forensics://ir-2026-0001/` | 2026-05-21 16:35 | jnowak |
| `ws01-ps-transcript.log` | `e3b8...` | `C:\PSLogs\` z WS01 | `forensics://ir-2026-0001/` | 2026-05-21 16:35 | jnowak |
| `wazuh-alerts-2026-05-21.json` | `1d7c...` | Wazuh Indexer export | `forensics://ir-2026-0001/` | 2026-05-21 17:00 | jnowak |

---

## 10. Załączniki

- `screenshots/dashboard-2026-05-21-1431.png` — pierwszy alert
- `screenshots/process-tree-explorer-dumper.png` — drzewo procesów
- `iocs/iocs.csv` — lista IoC do importu do TIP / firewall
- `queries/wazuh-hunt-followup.txt` — zapytania Wazuh do monitoringu post-incident

---

## Sign-off

| Rola | Imię i nazwisko | Data | Podpis |
|---|---|---|---|
| Analyst (tier 1) | | | |
| Analyst (tier 2) | | | |
| SOC Manager | | | |
| CISO (jeśli wymagane) | | | |

---

*Raport utworzony zgodnie z procedurą `SOP-IR-001-v3` (obowiązuje od 2026-01-01).*
*Klasyfikacja dokumentu: **INTERNAL — RESTRICTED**.*
