# run-procmon-probe.ps1 - run the P6 acceptance probe test inside the guest as a
# detached process (avoids Invoke-Command blocking on long-running Add-Type + 12s probe).
# Copies the C# client, launches a background guest PS process, polls for completion.
param(
    [string]$ClientCs = 'E:\Project\HTML\AnXinSecurity\vm-automation\probe-procmon-client.cs',
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-procmon-probe-test.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== run-procmon-probe @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started" }

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VMId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

try { Copy-Item -Path $ClientCs -Destination 'C:\Windows\Temp\probe-procmon-client.cs' -ToSession $s -Force; W "client copied" }
catch { W "ERROR: copy failed: $($_.Exception.Message)"; Remove-PSSession $s; exit 1 }

# write the guest runner script
$guestScript = @'
$ErrorActionPreference = 'Continue'
$log = 'C:\Windows\Temp\anxin-procmon-probe-guest.log'
"=== GUEST-PROBE @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
try {
    Add-Type -Path 'C:\Windows\Temp\probe-procmon-client.cs'
    $result = [ProbeTest]::Run()
    Add-Content $log $result
} catch {
    $msg = "COMPILE/RUN ERROR: $($_.Exception.Message)"
    Add-Content $log $msg
}
"=== GUEST-PROBE DONE @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
'@
Set-Content -LiteralPath (Join-Path $env:TEMP 'anxin-procmon-guest-runner.ps1') -Value $guestScript -Encoding UTF8

# launch detached inside the guest
Invoke-Command -Session $s -ScriptBlock {
    Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Windows\Temp\anxin-procmon-guest-runner.ps1' -WindowStyle Hidden
    "launched"
} | ForEach-Object { W $_ }
Remove-PSSession $s
W "guest runner launched, polling..."

# poll for the DONE marker
$done = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 3
    $s2 = $null
    $deadline2 = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline2) {
        try { $s2 = New-PSSession -VMId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
        Start-Sleep -Seconds 2
    }
    if (-not $s2) { W "poll reconnect failed"; break }
    $content = Invoke-Command -Session $s2 -ScriptBlock { if (Test-Path 'C:\Windows\Temp\anxin-procmon-probe-guest.log') { Get-Content 'C:\Windows\Temp\anxin-procmon-probe-guest.log' -Raw } else { '' } }
    Remove-PSSession $s2
    if ($content -match 'GUEST-PROBE DONE') { $done = $true; $content -split "`r?`n" | ForEach-Object { W $_ }; break }
}
if (-not $done) { W "TIMEOUT waiting for guest probe" }
W "=== run-procmon-probe done ==="
