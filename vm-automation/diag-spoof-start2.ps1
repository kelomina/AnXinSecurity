# diag-spoof-start.ps1 - v2: reliable name-prefix hang experiment.
# For each test exe (copied powershell), Start-Process hidden, then poll for the
# process by ExecutablePath (not by name) to avoid 15-byte ImageFileName truncation.
# verdict: EXITED if the process disappears within 10s, HANG if still running.
# Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-spoof-start2.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-spoof-start v2 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VMId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    $src = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    function Test2([string]$name) {
        $path = 'C:\Windows\Temp\' + $name + '.exe'
        try { Copy-Item $src $path -Force } catch { "TEST $name COPY-FAIL: $($_.Exception.Message)"; return }
        try {
            Start-Process $path -ArgumentList '-NoProfile','-Command','Write-Output done > C:\Windows\Temp\o2.txt 2>&1' -WindowStyle Hidden | Out-Null
        } catch { "TEST $name START-FAIL: $($_.Exception.Message)"; return }
        $dl = (Get-Date).AddSeconds(10); $still = $false
        while ((Get-Date) -lt $dl) {
            $procs = @(Get-CimInstance Win32_Process -Filter "ExecutablePath='$($path -replace "'","''")'" -ErrorAction SilentlyContinue)
            if ($procs.Count -eq 0) { $still = $false; break }
            $still = $true
            Start-Sleep -Milliseconds 800
        }
        if ($still) {
            $pids = @(Get-CimInstance Win32_Process -Filter "ExecutablePath='$($path -replace "'","''")'" -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessId })
            "TEST $name HANG pids=[$($pids -join ',')]"
            foreach ($pid2 in $pids) { & cmd.exe /c "taskkill /f /pid $pid2 2>&1" | Out-Null }
        } else {
            "TEST $name EXITED"
        }
        try { Remove-Item $path -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item 'C:\Windows\Temp\o2.txt' -Force -ErrorAction SilentlyContinue } catch {}
    }
    "=== GUEST-SPOOF-START2 @ $(Get-Date -Format HH:mm:ss) ==="
    Test2 'plain-copy2'
    Test2 'anxin-security-z'
    Test2 'anxin-security'
    "=== DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== diag-spoof-start v2 done ==="
