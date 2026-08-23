# antagonist-debug.ps1 - debug ETW Registry event capture in VM.
# Run registry write, then dump diagnostics + service log for analysis.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-debug.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== debug @ $(Get-Date -Format 'HH:mm:ss') ===" | Add-Content $LogPath
$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if ($vm.State -ne 'Running') { Start-VM -VM $vm; Start-Sleep -Seconds 20 }
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }

$r = Invoke-Command -Session $s -ScriptBlock {
    $out = @()
    $diag = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\runtime\interception_diagnostics.jsonl'
    $base = 0
    if (Test-Path $diag) { $base = (Get-Content $diag | Measure-Object -Line).Lines }

    # restart service for clean state
    sc.exe stop AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 4
    sc.exe start AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 6
    $out += "service restarted"

    # write a Run key as test user (interactive, direct reg.exe)
    $tmp = 'C:\Windows\Temp\regtest.ps1'
    @"
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'AnXinTest' -Value 'C:\Windows\notepad.exe' -Force
"@ | Set-Content -Path $tmp -Force
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmp`"" -PassThru
    $out += "launched reg write pid=$($p.Id)"
    Start-Sleep -Seconds 15

    # check diagnostics
    if (Test-Path $diag) {
        $lines = Get-Content $diag | Select-Object -Skip $base
        $out += "new diagnostics: $($lines.Count) lines"
        $lines | Select-Object -First 40 | ForEach-Object { $out += "  $_" }
    } else {
        $out += "diagnostics file not found"
    }

    # check process state
    $st = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
    if ($st) { $out += "reg write process: ALIVE cpu=$($st.CPU)" } else { $out += "reg write process: DEAD/EXITED" }

    # cleanup
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'AnXinTest' -Force -ErrorAction SilentlyContinue
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== debug done ==="