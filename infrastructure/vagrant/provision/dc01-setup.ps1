# =============================================================================
# DC01 — provisioning Windows Server 2019 jako kontroler domeny soclab.local
# Wywoływany przez Vagranta po pierwszym boocie.
# Idempotentny — może być uruchamiany wielokrotnie.
# =============================================================================

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
    Write-Host "[+] Adapter dla VLAN 20: '$($iface.Name)' (IP już $($ipAddr.IPAddress))"
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

    Write-Host "[+] Ustawiam statyczne IP 192.168.20.10/24 na adapterze '$($iface.Name)'"
    New-NetIPAddress -InterfaceIndex $iface.ifIndex `
                     -IPAddress 192.168.20.10 `
                     -PrefixLength 24 `
                     -DefaultGateway 192.168.20.1 -ErrorAction SilentlyContinue | Out-Null
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
if (-not (Get-WindowsFeature -Name AD-Domain-Services).Installed) {
    Write-Host "[+] Instaluję rolę AD-Domain-Services"
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
}

# Sprawdź czy domena już istnieje
$alreadyDC = $false
try {
    Get-ADDomain -ErrorAction Stop | Out-Null
    $alreadyDC = $true
} catch { }

if (-not $alreadyDC) {
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

    Write-Host "[!] Promocja zakończona. Restart wymagany — Vagrant zrestartuje VM po tym etapie."
    Restart-Computer -Force
    exit 0
}

# -----------------------------------------------------------------------------
# 4. Twórz konta testowe (po promocji, gdy już jesteśmy DC)
# -----------------------------------------------------------------------------
Import-Module ActiveDirectory

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

        if ($u.Admin) {
            Add-ADGroupMember -Identity "Domain Admins" -Members $u.Sam
        }
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
Write-Host "    Adminy:   SOCLAB\Administrator (P@ssw0rd!Lab), SOCLAB\akowalska"
