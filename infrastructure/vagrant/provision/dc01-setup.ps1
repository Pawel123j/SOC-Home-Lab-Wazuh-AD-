# =============================================================================
# DC01 — provisioning Windows Server 2019 jako kontroler domeny soclab.local
# Vagrant uruchamia Promote, wykonuje reboot, potem Configure.
# Oba etapy można ponowić przez vagrant provision dc01.
# =============================================================================

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Promote', 'Configure')]
    [string]$Phase,
    [ValidateRange(1, 120)]
    [int]$ReadyAttempts = 60,
    [ValidateRange(0, 60)]
    [int]$ReadyDelaySeconds = 10
)

$ErrorActionPreference = "Stop"
Write-Host "[+] DC01 provisioning — start"

# -----------------------------------------------------------------------------
# 1. Sieć: statyczne IP + DNS na samego siebie (po promocji)
# -----------------------------------------------------------------------------
# VM ma kilka kart (NAT + private_network) — wybieramy tę z IP w 192.168.20.0/24.
# Vagrant powinien był ustawić to IP, więc szukamy adaptera po IP, nie po kolejności.
$targetSubnet = '192.168.20.'
$ipAddr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -like "$targetSubnet*" } |
          Select-Object -First 1

if ($ipAddr) {
    $iface = Get-NetAdapter -InterfaceIndex $ipAddr.InterfaceIndex
    Write-Host "[+] Adapter dla sieci laboratoryjnej: '$($iface.Name)' (IP już $($ipAddr.IPAddress))"
} else {
    # Fallback: jeśli Vagrant jeszcze nie ustawił IP, weź pierwszy non-loopback non-NAT adapter
    $iface = Get-NetAdapter | Where-Object {
        $_.Status -eq 'Up' -and
        $_.Name -notlike '*Loopback*' -and
        # Pomijamy NAT (zazwyczaj 10.0.2.0/24 w VirtualBox)
        -not ((Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -like '10.0.2.*')
    } | Select-Object -First 1

    if (-not $iface) {
        Write-Error "[!] Nie znalazłem żadnego nadającego się adaptera sieciowego."
        exit 1
    }

    Write-Host "[+] Ustawiam statyczne IP 192.168.20.10/16 na adapterze '$($iface.Name)'"
    New-NetIPAddress -InterfaceIndex $iface.ifIndex `
                     -IPAddress 192.168.20.10 `
                     -PrefixLength 16 `
                     -ErrorAction Stop | Out-Null
}

# DNS na 127.0.0.1 (DC sam dla siebie po promocji)
Set-DnsClientServerAddress -InterfaceIndex $iface.ifIndex -ServerAddresses 127.0.0.1

# -----------------------------------------------------------------------------
# 2. Strefa czasowa
# -----------------------------------------------------------------------------
Set-TimeZone -Id "Central European Standard Time"

# -----------------------------------------------------------------------------
# 3. Instalacja roli AD DS i promocja
# -----------------------------------------------------------------------------
if ($Phase -eq 'Promote') {
    if (-not (Get-WindowsFeature -Name AD-Domain-Services).Installed) {
        Write-Host "[+] Instaluję rolę AD-Domain-Services"
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
    }

    # DomainRole jest lokalny; chwilowa niedostępność AD nie oznacza nowej domeny.
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) {
        Write-Host "[+] Promuję serwer na DC w nowej domenie soclab.local"
        $securePass = ConvertTo-SecureString "P@ssw0rd!Lab" -AsPlainText -Force

        Install-ADDSForest `
            -DomainName "soclab.local" `
            -DomainNetbiosName "SOCLAB" `
            -ForestMode "WinThreshold" `
            -DomainMode "WinThreshold" `
            -InstallDns:$true `
            -SafeModeAdministratorPassword $securePass `
            -NoRebootOnCompletion:$true `
            -Force:$true | Out-Null

    }
    Write-Host "[+] Etap Promote zakończony. Vagrant wykona restart przed Configure."
    return
}

# Po reboocie WinRM może być gotowy przed AD DS/ADWS. Nie pomijaj kont testowych.
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) {
    throw 'DC01 nie jest kontrolerem domeny. Uruchom vagrant provision dc01 (Promote + reboot + Configure).'
}
Import-Module ActiveDirectory
$domainReady = $false
for ($i = 0; $i -lt $ReadyAttempts; $i++) {
    try {
        Get-ADDomain -Identity 'soclab.local' -Server localhost -ErrorAction Stop | Out-Null
        $domainReady = $true
        break
    } catch {
        if ($i -lt ($ReadyAttempts - 1)) { Start-Sleep -Seconds $ReadyDelaySeconds }
    }
}
if (-not $domainReady) {
    throw 'AD DS nie jest gotowe po restarcie. Sprawdź DC01 i ponów vagrant provision dc01.'
}

# -----------------------------------------------------------------------------
# 4. Twórz konta testowe (po promocji, gdy już jesteśmy DC)
# -----------------------------------------------------------------------------
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'LabUsers'" -ErrorAction SilentlyContinue)) {
    Write-Host "[+] Tworzę OU=LabUsers"
    New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=soclab,DC=local"
}

$labUsers = @(
    @{ Sam = "akowalska"; Name = "Anna Kowalska"; Pass = "Wiosna2024!"; Admin = $true  },
    @{ Sam = "jnowak";    Name = "Jan Nowak";     Pass = "Lato2024!";   Admin = $false },
    @{ Sam = "svc-backup"; Name = "Backup Service"; Pass = "B@ckup!2024Lab"; Admin = $false }
)

foreach ($u in $labUsers) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
        Write-Host "[+] Tworzę użytkownika $($u.Sam)"
        New-ADUser -Name $u.Name `
                   -SamAccountName $u.Sam `
                   -UserPrincipalName "$($u.Sam)@soclab.local" `
                   -Path "OU=LabUsers,DC=soclab,DC=local" `
                   -AccountPassword (ConvertTo-SecureString $u.Pass -AsPlainText -Force) `
                   -Enabled $true `
                   -PasswordNeverExpires $true
    }
    if ($u.Admin) {
        Add-ADGroupMember -Identity "Domain Admins" -Members $u.Sam
    }
}

# -----------------------------------------------------------------------------
# 5. Włącz zaawansowany audyt (Security log)
# -----------------------------------------------------------------------------
Write-Host "[+] Konfiguruję politykę audytu"
auditpol /set /category:"Logon/Logoff"       /success:enable /failure:enable | Out-Null
auditpol /set /category:"Account Logon"      /success:enable /failure:enable | Out-Null
auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Privilege Use"      /success:enable /failure:enable | Out-Null
auditpol /set /category:"Detailed Tracking"  /success:enable                  | Out-Null
auditpol /set /category:"Object Access"      /success:enable /failure:enable | Out-Null
auditpol /set /category:"Policy Change"      /success:enable                  | Out-Null

# Zwiększ rozmiar Security log (domyślnie 20 MB — za mało)
wevtutil sl Security /ms:1073741824   # 1 GB
wevtutil sl System   /ms:268435456    # 256 MB

# Process creation z linią komend
$reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
Set-ItemProperty -Path $reg -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# -----------------------------------------------------------------------------
# 6. Firewall — otwórz porty potrzebne dla agenta Wazuh wychodzącego
# -----------------------------------------------------------------------------
New-NetFirewallRule -DisplayName "Wazuh-Out-1514" `
                    -Direction Outbound -Protocol TCP -RemotePort 1514 `
                    -Action Allow -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Wazuh-Out-1515" `
                    -Direction Outbound -Protocol TCP -RemotePort 1515 `
                    -Action Allow -ErrorAction SilentlyContinue | Out-Null

Write-Host "[+] DC01 provisioning — gotowe."
Write-Host "    Domena:   soclab.local"
Write-Host "    NetBIOS:  SOCLAB"
Write-Host "    Konto dołączenia WS01: SOCLAB\akowalska (hasło labowe z definicji użytkownika)."
Write-Host "    Hasło DSRM nie zmienia hasła konta Administrator."
