# 02 — Instalacja krok po kroku

Dokument prowadzi od pustej maszyny hostującej do działającego SIEM-a z agentami zbierającymi logi. Czas potrzebny: ~90 minut przy pierwszym uruchomieniu, z czego 60 min to pobieranie ISO i paczek.

---

## Spis treści

1. [Wymagania wstępne na hoście](#1-wymagania-wstępne-na-hoście)
2. [Postawienie maszyn przez Vagrant](#2-postawienie-maszyn-przez-vagrant)
3. [Instalacja Wazuh Managera (Ubuntu 22.04)](#3-instalacja-wazuh-managera-ubuntu-2204)
4. [Konfiguracja Active Directory na DC01](#4-konfiguracja-active-directory-na-dc01)
5. [Przyłączenie WS01 do domeny](#5-przyłączenie-ws01-do-domeny)
6. [Wdrożenie Sysmona z konfiguracją SwiftOnSecurity](#6-wdrożenie-sysmona-z-konfiguracją-swiftonsecurity)
7. [Instalacja agentów Wazuh przez Ansible](#7-instalacja-agentów-wazuh-przez-ansible)
8. [Weryfikacja end-to-end](#8-weryfikacja-end-to-end)
9. [Troubleshooting — najczęstsze błędy](#9-troubleshooting--najczęstsze-błędy)

---

## 1. Wymagania wstępne na hoście

Sprawdź na maszynie hostującej:

```powershell
# Windows
systeminfo | findstr /C:"Total Physical Memory"   # >= 16 GB
Get-WmiObject Win32_Processor | Select VirtualizationFirmwareEnabled  # True
```

```bash
# Linux / macOS
free -h            # >= 16 GB
egrep -c '(vmx|svm)' /proc/cpuinfo   # > 0
```

Zainstaluj:

| Narzędzie | Wersja | Komenda weryfikująca |
|---|---|---|
| VirtualBox | 7.0+ | `VBoxManage --version` |
| Vagrant | 2.4+ | `vagrant --version` |
| Ansible | 2.15+ (na hoście Linux/macOS lub WSL na Windows) | `ansible --version` |
| Git | dowolny | `git --version` |

W BIOS-ie: **VT-x / AMD-V** włączone. Bez tego maszyny 64-bit nie wystartują.

---

## 2. Postawienie maszyn przez Vagrant

```bash
git clone https://github.com/<twoj-user>/soc-home-lab.git
cd soc-home-lab/infrastructure/vagrant
vagrant up
```

`Vagrantfile` stawia cztery maszyny sekwencyjnie (zależnie od konfiguracji):

```
==> wazuh-srv: Importing base box 'ubuntu/jammy64'...
==> wazuh-srv: Booting VM...
==> wazuh-srv: Configuring network adapters...
==> dc01: Importing base box 'gusztavvargadr/windows-server-2019-standard'...
==> ws01: Importing base box 'gusztavvargadr/windows-10-enterprise'...
==> kali: Importing base box 'kalilinux/rolling'...
```

Po zakończeniu sprawdź:

```bash
vagrant status
# Powinno pokazać 4× running

# Test łączności:
vagrant ssh wazuh-srv -c "ping -c 2 192.168.20.10"
```

> **Tip:** jeśli `vagrant up` zawiesza się na `Waiting for SSH...` przy Windows, przyczyna to zazwyczaj WinRM. Sprawdź `vagrant winrm-config dc01` i ewentualnie zwiększ `config.winrm.timeout`.

---

## 3. Instalacja Wazuh Managera (Ubuntu 22.04)

W tym labie używam oficjalnego skryptu all-in-one (Wazuh ≥ 4.7). Wszystkie polecenia jako `root` na maszynie `wazuh-srv`.

### 3.1. Połącz się i przygotuj system

```bash
vagrant ssh wazuh-srv
sudo -i

apt update && apt upgrade -y
apt install -y curl gnupg2 apt-transport-https ca-certificates
timedatectl set-timezone Europe/Warsaw
hostnamectl set-hostname wazuh-srv
```

### 3.2. Uruchom installer

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Edytuj config.yml — wpisz IP managera:
sed -i 's|<wazuh-manager-ip>|192.168.10.10|g' config.yml

bash wazuh-install.sh --generate-config-files
bash wazuh-install.sh --wazuh-indexer  wazuh-srv
bash wazuh-install.sh --start-cluster
bash wazuh-install.sh --wazuh-server   wazuh-srv
bash wazuh-install.sh --wazuh-dashboard wazuh-srv
```

Hasła administracyjne wygenerowane przez installer leżą w `/etc/wazuh-passwords.txt` — **zachowaj je w bezpiecznym miejscu** (KeePass / Bitwarden). W produkcji ten plik kasujemy po zapisaniu sekretów.

### 3.3. Weryfikacja usług

```bash
systemctl status wazuh-manager   wazuh-indexer   wazuh-dashboard
ss -tlnp | grep -E "1514|1515|55000|443|9200"
```

Powinieneś zobaczyć trzy aktywne usługi i otwarte porty: 1514, 1515, 55000, 443, 9200.

### 3.4. Pierwsze logowanie

Otwórz w przeglądarce: `https://192.168.10.10`
Login: `admin` / hasło z `/etc/wazuh-passwords.txt`.

> **Uwaga:** certyfikat self-signed — w labie OK, w produkcji wystaw przez wewnętrzne CA.

### 3.5. Wgranie własnych reguł

```bash
# Skopiuj reguły z repo do managera
scp ../../detection-rules/custom-wazuh-rules.xml \
    vagrant@192.168.10.10:/tmp/

ssh vagrant@192.168.10.10
sudo cp /tmp/custom-wazuh-rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 660 /var/ossec/etc/rules/local_rules.xml

# Test składni przed restartem!
sudo /var/ossec/bin/wazuh-logtest -t

# Jeśli OK — restart managera
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/ossec.log
```

Jeśli w logu zobaczysz `INFO: Started (pid: ...)` — reguły załadowane.

---

## 4. Konfiguracja Active Directory na DC01

Na DC01 (zaloguj się przez RDP albo `vagrant rdp dc01`):

### 4.1. Promocja na DC

PowerShell jako Administrator:

```powershell
# Ustaw statyczne IP
New-NetIPAddress -InterfaceAlias "Ethernet" `
                 -IPAddress 192.168.20.10 `
                 -PrefixLength 24 `
                 -DefaultGateway 192.168.20.1

Set-DnsClientServerAddress -InterfaceAlias "Ethernet" `
                           -ServerAddresses 127.0.0.1

# Zmień nazwę i zrestartuj
Rename-Computer -NewName "DC01" -Restart

# Po reboocie — instalacja roli AD DS
Install-WindowsFeature -Name AD-Domain-Services `
                       -IncludeManagementTools

# Promocja na pierwszy kontroler nowej domeny
Install-ADDSForest `
    -DomainName "soclab.local" `
    -DomainNetbiosName "SOCLAB" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd!Lab" -AsPlainText -Force) `
    -Force
# Maszyna sama się zrestartuje
```

### 4.2. Stwórz konta testowe

Po restarcie, jako `SOCLAB\Administrator`:

```powershell
# OU dla użytkowników labowych
New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=soclab,DC=local"

# Konto administratora domenowego do testów
New-ADUser -Name "Anna Kowalska" `
           -SamAccountName "akowalska" `
           -UserPrincipalName "akowalska@soclab.local" `
           -Path "OU=LabUsers,DC=soclab,DC=local" `
           -AccountPassword (ConvertTo-SecureString "Wiosna2024!" -AsPlainText -Force) `
           -Enabled $true

Add-ADGroupMember -Identity "Domain Admins" -Members akowalska

# Zwykły user (do scenariuszy phishingowych)
New-ADUser -Name "Jan Nowak" `
           -SamAccountName "jnowak" `
           -UserPrincipalName "jnowak@soclab.local" `
           -Path "OU=LabUsers,DC=soclab,DC=local" `
           -AccountPassword (ConvertTo-SecureString "Lato2024!" -AsPlainText -Force) `
           -Enabled $true
```

### 4.3. Włącz zaawansowany audyt

Bez tego nie zobaczymy ważnych zdarzeń (np. EventID 4624 z typem 3 dla logowania zdalnego).

```powershell
auditpol /set /category:"Logon/Logoff"       /success:enable /failure:enable
auditpol /set /category:"Account Logon"      /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Privilege Use"      /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking"  /success:enable
auditpol /set /category:"Object Access"      /success:enable /failure:enable
auditpol /set /category:"Policy Change"      /success:enable

# Zwiększ rozmiar logów (domyślnie 20 MB to za mało)
wevtutil sl Security /ms:1073741824     # 1 GB
wevtutil sl System   /ms:268435456      # 256 MB
```

---

## 5. Przyłączenie WS01 do domeny

Na WS01:

```powershell
# Statyczne IP
New-NetIPAddress -InterfaceAlias "Ethernet" `
                 -IPAddress 192.168.20.20 `
                 -PrefixLength 24 `
                 -DefaultGateway 192.168.20.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" `
                           -ServerAddresses 192.168.20.10

# Test rozwiązywania DNS
Resolve-DnsName soclab.local
nltest /dsgetdc:soclab.local

# Dołącz do domeny
Add-Computer -DomainName "soclab.local" `
             -Credential (Get-Credential SOCLAB\Administrator) `
             -NewName "WS01" `
             -Restart
```

Po restarcie zaloguj się jako `SOCLAB\akowalska`.

---

## 6. Wdrożenie Sysmona z konfiguracją SwiftOnSecurity

Sysmon to **must-have** w SOC — daje nam Event ID 1 (ProcessCreate z pełną linią komend), Event ID 3 (NetworkConnect), Event ID 7 (ImageLoad), Event ID 10 (ProcessAccess — kluczowe dla detekcji Mimikatza), Event ID 11 (FileCreate), Event ID 22 (DNS query).

Na DC01 i WS01:

```powershell
# Pobierz Sysmon
$url = "https://download.sysinternals.com/files/Sysmon.zip"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force

# Pobierz konfigurację SwiftOnSecurity (de facto standard w SOC)
$cfg = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
Invoke-WebRequest -Uri $cfg -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Instalacja jako service
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml

# Weryfikacja
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### Włącz zaawansowane logowanie PowerShell

Również krytyczne — bez tego nie zobaczymy zaciemnionych komend (encoded commands, ScriptBlock):

```powershell
# Włącz logowanie skryptów PowerShell
$reg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $reg -Force | Out-Null
Set-ItemProperty -Path $reg -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Module logging
$reg2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $reg2 -Force | Out-Null
Set-ItemProperty -Path $reg2 -Name "EnableModuleLogging" -Value 1 -Type DWord
New-Item -Path "$reg2\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$reg2\ModuleNames" -Name "*" -Value "*" -Type String

# Transkrypcja (opcjonalne, generuje dużo danych)
$reg3 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $reg3 -Force | Out-Null
Set-ItemProperty -Path $reg3 -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $reg3 -Name "OutputDirectory" -Value "C:\PSLogs" -Type String
```

---

## 7. Instalacja agentów Wazuh przez Ansible

W repo: `infrastructure/ansible/`. Na hoście (lub w WSL):

```bash
cd infrastructure/ansible

# Sprawdź inwentarz
cat inventory.yml

# Test łączności
ansible -i inventory.yml all -m ping

# Wdrożenie pełne (manager już stoi, doinstalowanie agentów)
ansible-playbook -i inventory.yml site.yml
```

Playbook `site.yml`:
1. Pobiera odpowiedni pakiet agenta (MSI dla Windows, DEB dla Ubuntu),
2. Instaluje agenta z parametrami: `WAZUH_MANAGER=192.168.10.10`, `WAZUH_REGISTRATION_SERVER=192.168.10.10`,
3. Uruchamia usługę,
4. Sprawdza w API managera, że agent jest `active`.

### Walidacja po stronie managera

```bash
ssh vagrant@192.168.10.10
sudo /var/ossec/bin/agent_control -l
```

Spodziewany output:

```
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh-srv (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: dc01, IP: 192.168.20.10, Active
   ID: 002, Name: ws01, IP: 192.168.20.20, Active
```

---

## 8. Weryfikacja end-to-end

Test 1 — czy z DC01 trafiają zdarzenia Security:

```powershell
# Na DC01:
runas /user:nieistnieje cmd   # celowo zły login
```

Po 5 sekundach w dashboardzie Wazuh (`Discover` → indeks `wazuh-alerts-*`):

```
rule.id: 60122   # Logon failure
agent.name: dc01
data.win.eventdata.targetUserName: nieistnieje
```

Test 2 — czy Sysmon strzela:

```powershell
# Na WS01:
powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==
```

W dashboardzie powinien pojawić się alert oparty o naszą regułę **100212** (`Suspicious PowerShell EncodedCommand`).

Test 3 — czy agent przeżywa restart:

```bash
# Na wazuh-srv:
sudo systemctl restart wazuh-manager
sleep 30
sudo /var/ossec/bin/agent_control -l   # wszyscy powinni być Active
```

---

## 9. Troubleshooting — najczęstsze błędy

| Objaw | Przyczyna | Rozwiązanie |
|---|---|---|
| Agent `Disconnected` po instalacji | Firewall na endpointach blokuje 1514 wychodzące | `New-NetFirewallRule -DisplayName "Wazuh-Out" -Direction Outbound -Protocol TCP -RemotePort 1514 -Action Allow` |
| `wazuh-indexer` nie startuje, OOM w dmesg | Za mało RAM dla JVM | `/etc/wazuh-indexer/jvm.options` → `-Xms1g -Xmx1g` |
| Dashboard pokazuje "No alerts" mimo, że są w `/var/ossec/logs/alerts/alerts.json` | Indeks nie jest tworzony | Sprawdź `curl -u admin:HASLO -k https://localhost:9200/_cat/indices` — czy istnieje `wazuh-alerts-4.x-YYYY.MM.DD` |
| `wazuh-logtest -t` zwraca błąd składni XML | Pomyłka w `local_rules.xml` | Czytaj uważnie numer linii w błędzie; częsta wina to brak zamknięcia `</group>` |
| Brak EventID 4688 (Process Create) z linią komend | Audyt PolicyChange wyłączony lub brak GPO | `auditpol /set /subcategory:"Process Creation" /success:enable` + GPO `Include command line in process creation events` = Enabled |
| Sigma → Wazuh: reguła nie strzela | Mapowanie pól (`process.command_line` vs `data.win.eventdata.commandLine`) | Użyj `sigma convert -t wazuh` aktualnej wersji `pysigma-backend-elasticsearch` z plugin `wazuh-mapping` |
| Czas alertów przesunięty o 2 h | Strefa czasowa różna na agencie i managerze | `timedatectl set-timezone Europe/Warsaw` na obu, restart agenta |

---

Kolejny krok: [03-attack-scenarios.md](03-attack-scenarios.md) — 5 scenariuszy ataków z mapowaniem MITRE.
