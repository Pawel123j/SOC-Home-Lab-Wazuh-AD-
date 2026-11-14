# Exercise the real phase scripts with Windows commands replaced by local stubs.
# This verifies control flow only; it does not emulate AD, WinRM or Sysmon.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$dcScript = Join-Path $repoRoot 'infrastructure/vagrant/provision/dc01-setup.ps1'
$wsScript = Join-Path $repoRoot 'infrastructure/vagrant/provision/ws01-setup.ps1'

# Parse every PowerShell source without executing any attack scenario.
foreach ($file in Get-ChildItem $repoRoot -Recurse -Filter '*.ps1') {
    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw "$($file.FullName): $parseErrors" }
}

function Reset-State {
    $script:state = @{
        Calls = [System.Collections.Generic.List[string]]::new()
        DomainRole = 5; Joined = $true; Domain = 'soclab.local'
        ADFailures = 0; DNSFailures = 0; TrustFailures = 0; LDAPReady = $true
        ADChecks = 0; DNSChecks = 0; TrustChecks = 0
    }
}
function Record([string]$Name) { $script:state.Calls.Add($Name) }
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Assertion failed: $Message" }
}
function Invoke-Phase([string]$Script, [string]$Phase, [string]$ExpectedError = '') {
    $failure = ''
    # Dot-source in this per-invocation function so mocks keep the test script's
    # state scope, while provisioning variables remain local to this invocation.
    try { . $Script -Phase $Phase -ReadyAttempts 3 -ReadyDelaySeconds 0 }
    catch { $failure = $_.Exception.Message }
    if ($ExpectedError) {
        Assert-True ($failure -like "*$ExpectedError*") "Expected '$ExpectedError', received '$failure'"
    } else {
        Assert-True (-not $failure) "Unexpected failure: $failure"
    }
}

# Never call networking, registry, service or host configuration cmdlets here.
function Get-NetIPAddress { [pscustomobject]@{ IPAddress = '192.168.20.10'; InterfaceIndex = 2 } }
function Get-NetAdapter { [pscustomobject]@{ Name = 'Lab'; ifIndex = 2 } }
function Set-DnsClientServerAddress {}
function Set-TimeZone {}
function Get-CimInstance {
    [pscustomobject]@{ DomainRole = $script:state.DomainRole; PartOfDomain = $script:state.Joined; Domain = $script:state.Domain }
}
function Get-WindowsFeature { [pscustomobject]@{ Installed = $false } }
function Install-WindowsFeature { Record 'install-role' }
function Install-ADDSForest { Record 'promote' }
function Import-Module { Record 'import-ad' }
function Get-ADDomain {
    $script:state.ADChecks++
    if ($script:state.ADChecks -le $script:state.ADFailures) { throw 'ADWS starting' }
    [pscustomobject]@{ DNSRoot = 'soclab.local' }
}
function Get-ADOrganizationalUnit { $null }
function New-ADOrganizationalUnit { Record 'create-ou' }
function Get-ADUser { $null }
function New-ADUser { Record 'create-user' }
function Add-ADGroupMember { Record 'add-admin' }
function auditpol { throw 'AUDIT_REACHED' }
function Start-Sleep { Record 'wait' }
function Resolve-DnsName {
    $script:state.DNSChecks++
    if ($script:state.DNSChecks -le $script:state.DNSFailures) { throw 'DNS starting' }
    [pscustomobject]@{ NameTarget = 'dc01.soclab.local' }
}
function Test-NetConnection { $script:state.LDAPReady }
function Add-Computer {
    param($DomainName, $Credential, [switch]$Force)
    Assert-True ($Credential.UserName -eq 'SOCLAB\akowalska') 'Join must use the provisioned domain admin'
    Record 'join'
}
function Test-ComputerSecureChannel {
    $script:state.TrustChecks++
    if ($script:state.TrustChecks -le $script:state.TrustFailures) { throw 'Netlogon starting' }
    $true
}
function Test-Path { $true }
function Get-Service { throw 'SYSMON_REACHED' }
function Restart-Computer { throw 'Unexpected in-script reboot' }

Reset-State
$state.DomainRole = 3
Invoke-Phase $dcScript Promote
Assert-True ($state.Calls.Contains('promote')) 'Fresh DC must be promoted'
Assert-True (-not $state.Calls.Contains('create-user')) 'User creation must wait for reboot'

Reset-State
Invoke-Phase $dcScript Promote
Assert-True (-not $state.Calls.Contains('promote')) 'Existing DC must not be promoted again'

Reset-State
$state.ADFailures = 2
Invoke-Phase $dcScript Configure AUDIT_REACHED
Assert-True ($state.ADChecks -eq 3) 'DC must retry AD readiness'
Assert-True (@($state.Calls | Where-Object { $_ -eq 'create-user' }).Count -eq 3) 'Configure must create all lab accounts'
Assert-True ($state.Calls.Contains('add-admin')) 'Join account must be a domain admin'

Reset-State
$state.ADFailures = 3
Invoke-Phase $dcScript Configure 'AD DS nie jest gotowe'
Assert-True ($state.ADChecks -eq 3 -and -not $state.Calls.Contains('create-user')) 'Readiness timeout must stop before creating users'

Reset-State
$state.DomainRole = 3
Invoke-Phase $dcScript Configure 'nie jest kontrolerem domeny'
Assert-True ($state.ADChecks -eq 0) 'Configure must reject an unpromoted DC'

Reset-State
$state.Joined = $false
$state.Domain = 'WORKGROUP'
$state.DNSFailures = 2
Invoke-Phase $wsScript Join
Assert-True ($state.DNSChecks -eq 3 -and $state.Calls.Contains('join')) 'WS must wait and join before returning for reboot'
Assert-True ($state.TrustChecks -eq 0) 'Join must not run the post-reboot phase'

Reset-State
Invoke-Phase $wsScript Join
Assert-True (-not $state.Calls.Contains('join')) 'Existing joined WS must not rejoin'

Reset-State
$state.LDAPReady = $false
Invoke-Phase $wsScript Join 'DC01 nie jest gotowy'
Assert-True ($state.DNSChecks -eq 3 -and -not $state.Calls.Contains('join')) 'An available DNS record alone must not permit joining'

Reset-State
$state.Domain = 'other.local'
Invoke-Phase $wsScript Join 'należy do innej domeny'
Assert-True (-not $state.Calls.Contains('join')) 'Do not move a host from another domain'

Reset-State
$state.Joined = $false
Invoke-Phase $wsScript Configure 'nie jest w soclab.local'
Assert-True ($state.TrustChecks -eq 0) 'Reject unjoined WS before configuring telemetry'

Reset-State
$state.TrustFailures = 2
Invoke-Phase $wsScript Configure SYSMON_REACHED
Assert-True ($state.TrustChecks -eq 3) 'Configure must retry trust readiness before Sysmon'

Reset-State
$state.TrustFailures = 3
Invoke-Phase $wsScript Configure 'Kanał zaufania WS01 do domeny nie działa'
Assert-True ($state.TrustChecks -eq 3) 'Trust failure must stop before Sysmon'

Write-Host 'PASS: PowerShell parsing and 12 mocked provisioning scenarios (no Windows runtime validation).'
