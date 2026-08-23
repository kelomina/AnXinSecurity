# diag-spoof-start.ps1 - controlled experiment: does the driver hang a NEW process
# based on its EXE NAME prefix? Uses Start-Process + file redirection (isolates the
# PS Direct output pipe). Compares:
#   plain-copy.exe       (no "anxin" in name, Temp dir)      -> expect normal
#   anxin-spoof3.exe     (anxin- prefix, name != anxin-security) -> observe
#   anxin-security-x.exe (matches 14-char "anxin-security" prefix) -> observe
# Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-spoof-start.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-spoof-start @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VMId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    function Test-Spoof([string]$name) {
        $src = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $path = 'C:\Windows\Temp\' + $name + '.exe'
        $o = 'C:\Windows\Temp\out-' + $name + '.txt'
        $e = 'C:\Windows\Temp\err-' + $name + '.txt'
        try { Copy-Item $src $path -Force } catch { "TEST $name COPY-FAIL: $($_.Exception.Message)"; return }
        try {
            $p = Start-Process $path -ArgumentList '-NoProfile','-Command','Write-Output done' -PassThru -WindowStyle Hidden `
                 -RedirectStandardOutput $o -RedirectStandardError $e
        } catch { "TEST $name START-FAIL: $($_.Exception.Message)"; return }
        $dl = (Get-Date).AddSeconds(15); $exited = $false
        while ((Get-Date) -lt $dl) { $p.Refresh(); if ($p.HasExited) { $exited = $true; break }; Start-Sleep -Milliseconds 700 }
        Start-Sleep -Milliseconds 300
        $outTxt = if (Test-Path $o) { (Get-Content $o -Raw).Trim() } else { '' }
        $errTxt = if (Test-Path $e) { (Get-Content $e -Raw).Trim() } else { '' }
        "TEST $name EXITED=$exited CODE=$(if ($p.HasExited) { $p.ExitCode } else { 'HANG' }) OUT=[$outTxt] ERR=[$errTxt]"
        try { Remove-Item $path -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item $o,$e -Force -ErrorAction SilentlyContinue } catch {}
    }
    "=== GUEST-SPOOF-START @ $(Get-Date -Format HH:mm:ss) ==="
    Test-Spoof 'plain-copy'
    Test-Spoof 'anxin-spoof3'
    Test-Spoof 'anxin-security-x'
    "=== DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== diag-spoof-start done ==="
