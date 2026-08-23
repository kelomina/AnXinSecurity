# fp-query.ps1 - query the FileProtect driver's protection path list from inside
# the VM via the app's own CLI (authorized channel), to learn exactly which paths
# block raw writes during deployment.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-fp-query.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== fp-query @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started" }

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$sysScript = @'
$exe = 'C:\Program Files\AnXinSecurity\anxin-security.exe'
& $exe --query-file-protect 2>&1 | Out-String | Set-Content 'C:\Windows\Temp\anxin-deploy\fp-query.log'
'fp query done' | Add-Content 'C:\Windows\Temp\anxin-deploy\fp-query.log'
'@
Invoke-Command -Session $s -ScriptBlock {
    param($c)
    New-Item -ItemType Directory -Path 'C:\Windows\Temp\anxin-deploy' -Force | Out-Null
    [System.IO.File]::WriteAllText('C:\Windows\Temp\anxin-deploy\fp-query.ps1', $c, (New-Object System.Text.UTF8Encoding($false)))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Windows\Temp\anxin-deploy\fp-query.ps1"'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinFpQuery' -InputObject $task -Force -ErrorAction SilentlyContinue | Out-Null
    Start-ScheduledTask -TaskName 'AnXinFpQuery'
    'scheduled'
} -ArgumentList $sysScript | ForEach-Object { W "  $_" }

Start-Sleep -Seconds 15
$r = Invoke-Command -Session $s -ScriptBlock {
    if (Test-Path 'C:\Windows\Temp\anxin-deploy\fp-query.log') { Get-Content 'C:\Windows\Temp\anxin-deploy\fp-query.log' } else { 'NO LOG' }
}
$r | ForEach-Object { W "  $_" }
Remove-PSSession $s
W "=== fp-query done ==="
