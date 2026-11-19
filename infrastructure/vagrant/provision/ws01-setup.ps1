# =============================================================================
# WS01 — provisioning Windows 10 jako stacja robocza w domenie soclab.local
# Czeka aż DC01 będzie gotowy, dołącza do domeny, instaluje Sysmon,
# konfiguruje logging PowerShell.
# =============================================================================

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Join', 'Configure')]
    [string]$Phase,
    [ValidateRange(1, 120)]
    [int]$ReadyAttempts = 60,
    [ValidateRange(0, 60)]
    [int]$ReadyDelaySeconds = 10
)

$ErrorActionPreference = "Stop"

# SOC-01: to samo hasło co przy tworzeniu konta na DC01 (LAB_AKOWALSKA_PASSWORD, domyślnie jawne hasło laboratoryjne).
function Get-LabSecret([string]$Name, [string]$LabDefault) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $LabDefault }
    return $value
}
Write-Host "[+] WS01 provisioning — start"

# -----------------------------------------------------------------------------
# 1. Sieć: statyczne IP + DNS na DC01
# -----------------------------------------------------------------------------
# VM ma kilka kart (NAT + private_network) — wybieramy tę z IP w 192.168.20.0/24.
$targetSubnet = '192.168.20.'
$ipAddr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -like "$targetSubnet*" } |
          Select-Object -First 1

if ($ipAddr) {
    $iface = Get-NetAdapter -InterfaceIndex $ipAddr.InterfaceIndex
    Write-Host "[+] Adapter dla sieci laboratoryjnej: '$($iface.Name)' (IP już $($ipAddr.IPAddress))"
} else {
    # Fallback: pierwszy adapter Up niebędący loopback ani NAT
    $iface = Get-NetAdapter | Where-Object {
        $_.Status -eq 'Up' -and
        $_.Name -notlike '*Loopback*' -and
        -not ((Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -like '10.0.2.*')
    } | Select-Object -First 1

    if (-not $iface) {
        Write-Error "[!] Nie znalazłem żadnego nadającego się adaptera sieciowego."
        exit 1
    }

    Write-Host "[+] Ustawiam statyczne IP 192.168.20.20/16 na adapterze '$($iface.Name)'"
    New-NetIPAddress -InterfaceIndex $iface.ifIndex `
                     -IPAddress 192.168.20.20 `
                     -PrefixLength 16 `
                     -ErrorAction Stop | Out-Null
}

Set-DnsClientServerAddress -InterfaceIndex $iface.ifIndex -ServerAddresses 192.168.20.10
Set-TimeZone -Id "Central European Standard Time"

# -----------------------------------------------------------------------------
# 2. Etap Join: poczekaj na rekord usługi AD i LDAP, nie tylko rekord A hosta
# -----------------------------------------------------------------------------
if ($Phase -eq 'Join') {
    $dcReady = $false
    for ($i = 0; $i -lt $ReadyAttempts; $i++) {
        try {
            Resolve-DnsName '_ldap._tcp.dc._msdcs.soclab.local' -Type SRV -Server 192.168.20.10 -ErrorAction Stop | Out-Null
            if (-not (Test-NetConnection -ComputerName 192.168.20.10 -Port 389 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
                throw 'LDAP nie jest jeszcze dostępny.'
            }
            $dcReady = $true
            break
        } catch {
            Write-Host "[..] DC01 jeszcze nie gotowy ($($i + 1)/$ReadyAttempts)"
            if ($i -lt ($ReadyAttempts - 1)) { Start-Sleep -Seconds $ReadyDelaySeconds }
        }
    }

    if (-not $dcReady) {
        throw "DC01 nie jest gotowy. Dokończ vagrant provision dc01, potem ponów vagrant provision ws01."
    }
    # -------------------------------------------------------------------------
    # 3. Dołączenie do domeny (idempotentne)
    # -------------------------------------------------------------------------
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.PartOfDomain -and $computer.Domain -ne 'soclab.local') {
        throw "WS01 należy do innej domeny: $($computer.Domain)."
    }
    if (-not $computer.PartOfDomain) {
        Write-Host "[+] Dołączam do domeny soclab.local"
        $cred = New-Object System.Management.Automation.PSCredential `
                    ("SOCLAB\akowalska", (ConvertTo-SecureString (Get-LabSecret "LAB_AKOWALSKA_PASSWORD" "Wiosna2024!") -AsPlainText -Force))
        Add-Computer -DomainName "soclab.local" -Credential $cred -Force
    }
    Write-Host '[+] Etap Join zakończony. Vagrant wykona restart przed Configure.'
    return
}

$computer = Get-CimInstance Win32_ComputerSystem
if (-not $computer.PartOfDomain -or $computer.Domain -ne 'soclab.local') {
    throw 'WS01 nie jest w soclab.local. Uruchom vagrant provision ws01 (Join + reboot + Configure).'
}
$channelReady = $false
for ($i = 0; $i -lt $ReadyAttempts; $i++) {
    try {
        if (Test-ComputerSecureChannel -Server 'dc01.soclab.local' -ErrorAction Stop) {
            $channelReady = $true
            break
        }
    } catch {
        Write-Host '[..] Kanał zaufania jeszcze nie jest gotowy po restarcie.'
    }
    if ($i -lt ($ReadyAttempts - 1)) { Start-Sleep -Seconds $ReadyDelaySeconds }
}
if (-not $channelReady) {
    throw 'Kanał zaufania WS01 do domeny nie działa. Sprawdź DC01 przed konfiguracją logowania.'
}

# -----------------------------------------------------------------------------
# 4. Instalacja Sysmona z konfiguracją SwiftOnSecurity
# -----------------------------------------------------------------------------
$sysmonPath = "C:\Tools\Sysmon"
if (-not (Test-Path "$sysmonPath\Sysmon64.exe")) {
    Write-Host "[+] Pobieram Sysmona"
    New-Item -ItemType Directory -Path $sysmonPath -Force | Out-Null

    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
                      -OutFile "$env:TEMP\Sysmon.zip" -UseBasicParsing
    Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath $sysmonPath -Force
}
# Nieudane pobranie konfiguracji można bezpiecznie ponowić po rozpakowaniu EXE.
if (-not (Test-Path "$sysmonPath\sysmonconfig.xml")) {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
                      -OutFile "$sysmonPath\sysmonconfig.xml" -UseBasicParsing
}

if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
    Write-Host "[+] Instaluję service Sysmon"
    & "$sysmonPath\Sysmon64.exe" -accepteula -i "$sysmonPath\sysmonconfig.xml" | Out-Null
} else {
    Write-Host "[=] Sysmon już zainstalowany — aktualizuję konfig"
    & "$sysmonPath\Sysmon64.exe" -c "$sysmonPath\sysmonconfig.xml" | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw "Sysmon zakończył się kodem $LASTEXITCODE." }

# -----------------------------------------------------------------------------
# 5. PowerShell — zaawansowane logowanie
# -----------------------------------------------------------------------------
Write-Host "[+] Włączam ScriptBlockLogging i ModuleLogging"

$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $psLogPath -Force | Out-Null
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

$psModPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $psModPath -Force | Out-Null
Set-ItemProperty -Path $psModPath -Name "EnableModuleLogging" -Value 1 -Type DWord
New-Item -Path "$psModPath\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$psModPath\ModuleNames" -Name "*" -Value "*" -Type String

# Transcript do C:\PSLogs
$psTrans = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $psTrans -Force | Out-Null
Set-ItemProperty -Path $psTrans -Name "EnableTranscripting"      -Value 1 -Type DWord
Set-ItemProperty -Path $psTrans -Name "OutputDirectory"          -Value "C:\PSLogs" -Type String
Set-ItemProperty -Path $psTrans -Name "EnableInvocationHeader"   -Value 1 -Type DWord

New-Item -ItemType Directory -Path "C:\PSLogs" -Force | Out-Null

# -----------------------------------------------------------------------------
# 6. Audyt
# -----------------------------------------------------------------------------
auditpol /set /category:"Logon/Logoff"       /success:enable /failure:enable | Out-Null
auditpol /set /category:"Account Logon"      /success:enable /failure:enable | Out-Null
auditpol /set /category:"Detailed Tracking"  /success:enable                  | Out-Null
auditpol /set /category:"Object Access"      /success:enable /failure:enable | Out-Null

wevtutil sl Security /ms:536870912   # 512 MB
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456 # 256 MB

# Process creation z linią komend
$reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
Set-ItemProperty -Path $reg -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# -----------------------------------------------------------------------------
# 7. Skopiuj skrypty ataków (do testów)
# -----------------------------------------------------------------------------
$attackDir = "C:\attacks"
New-Item -ItemType Directory -Path $attackDir -Force | Out-Null
if (Test-Path "C:\vagrant_repo\attacks") {
    Copy-Item -Path "C:\vagrant_repo\attacks\*" -Destination $attackDir -Recurse -Force
    Write-Host "[+] Skrypty ataków skopiowane do $attackDir"
}

# -----------------------------------------------------------------------------
# 8. Firewall — wyłącz Defender Real-Time, żeby nie blokował skryptów testowych
#    (CELOWO — to lab; w produkcji NIGDY)
# -----------------------------------------------------------------------------
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\attacks" -ErrorAction SilentlyContinue

Write-Host "[+] WS01 provisioning — gotowe."
Write-Host "    Domena: soclab.local, host: ws01.soclab.local"
Write-Host "    Sysmon, PS logging, audyt — włączone."
Write-Host "    Defender Real-Time wyłączony (CELOWO dla labu)."
