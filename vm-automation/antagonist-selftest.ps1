# antagonist-selftest.ps1 - controlled self-test: deploy a benign VBS that writes
# to HKCU Run, run it as the test user, and verify the interception chain fires
# (diagnostics queue_push + process suspended) with the deployed 7 test rules.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-selftest.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== antagonist-selftest @ $(Get-Date -Format 'HH:mm:ss') ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if ($vm.State -ne 'Running') { Start-VM -VM $vm; Start-Sleep -Seconds 20 }
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }
W "PS Direct connected"

$diag = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\runtime\interception_diagnostics.jsonl'
$base = Invoke-Command -Session $s -ScriptBlock { param($f) if (Test-Path $f) { (Get-Content $f | Measure-Object -Line).Lines } else { 0 } } -ArgumentList $diag

# write benign vbs to VM (writes a Run key value, sleeps, exits)
$vbs = @'
Set WshShell = CreateObject("WScript.Shell")
WshShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AnXinSelfTest", "C:\Samples\selftest\poc.exe", "REG_SZ"
WScript.Sleep 3000
'@
$localVbs = "$env:TEMP\anxin_selftest.vbs"
[System.IO.File]::WriteAllText($localVbs, $vbs, (New-Object System.Text.UTF8Encoding($false)))
Invoke-Command -Session $s -ScriptBlock { param($d) New-Item -ItemType Directory -Path $d -Force | Out-Null } -ArgumentList 'C:\Samples\selftest'
Copy-Item -LiteralPath $localVbs -Destination 'C:\Samples\selftest\poc.vbs' -ToSession $s -Force
W "benign vbs copied"

# restart service for clean state
Invoke-Command -Session $s -ScriptBlock {
    sc.exe stop AnXinSecurityService 2>&1 | Out-Null; Start-Sleep -Seconds 4
    sc.exe start AnXinSecurityService 2>&1 | Out-Null; Start-Sleep -Seconds 6
    'service reset'
} | ForEach-Object { W "  $_" }

# run it
$launch = Invoke-Command -Session $s -ScriptBlock {
    $p = Start-Process -FilePath 'wscript.exe' -ArgumentList '"C:\Samples\selftest\poc.vbs"' -PassThru
    @{ Pid = $p.Id }
}
W "launched wscript pid=$($launch.Pid)"
Start-Sleep -Seconds 12

# check process state
$st = Invoke-Command -Session $s -ScriptBlock {
    $p = Get-Process -Id $args[0] -ErrorAction SilentlyContinue
    if ($p) { "ALIVE cpu=$($p.CPU) start=$($p.StartTime.ToString('HH:mm:ss'))" } else { "DEAD/EXITED" }
} -ArgumentList $launch.Pid
W "wscript state: $st"

# check new diagnostics
$new = Invoke-Command -Session $s -ScriptBlock { param($f,$b) if (Test-Path $f) { Get-Content $f | Select-Object -Skip $b } else { @() } } -ArgumentList $diag, $base
W "new diagnostics lines: $($new.Count)"
$new | Select-Object -First 30 | ForEach-Object { W "  $_" }

# cleanup
Invoke-Command -Session $s -ScriptBlock {
    Stop-Process -Id $args[0] -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'AnXinSelfTest' -Force -ErrorAction SilentlyContinue
    Remove-Item 'C:\Samples' -Recurse -Force -ErrorAction SilentlyContinue
} -ArgumentList $launch.Pid

Remove-PSSession $s
W "=== selftest done ==="
