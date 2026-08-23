# antagonist-deploy-build.ps1 - deploy the freshly built release binary to the VM
# and enable headlessAutoTerminate in the packaged app.json, then restart the
# AnXinSecurityService. Uses a SYSTEM scheduled task so FileProtect lets us write
# under Program Files (same mechanism as antagonist-deploy-rules.ps1).
param(
    [string]$ExePath = 'E:\Project\HTML\AnXinSecurity\src-tauri\target\x86_64-pc-windows-msvc\release\anxin-security.exe',
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-deploy-build.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== deploy-build @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

if (-not (Test-Path $ExePath)) { W "ERROR: release exe not found at $ExePath (build first)"; exit 1 }
$exeBytes = (Get-Item $ExePath).Length
W "release exe: $ExePath ($exeBytes B)"

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

# 1. stage new exe into VM temp
$vmTempDir = 'C:\Windows\Temp\anxin-deploy'
Invoke-Command -Session $s -ScriptBlock { param($d) New-Item -ItemType Directory -Path $d -Force | Out-Null } -ArgumentList $vmTempDir
$vmTempExe = "$vmTempDir\anxin-security.exe"
Copy-Item -LiteralPath $ExePath -Destination $vmTempExe -ToSession $s -Force
W "staged exe -> $vmTempExe"

# 2. write the SYSTEM-side install script that swaps exe + injects config + restarts
$sysScript = @'
$ErrorActionPreference = 'Continue'
$log = 'C:\Windows\Temp\anxin-deploy\sys-deploy.log'
"sys-deploy @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content $log
sc.exe stop AnXinSecurityService 2>&1 | Out-Null
Start-Sleep -Seconds 5
# swap exe
Copy-Item -LiteralPath 'C:\Windows\Temp\anxin-deploy\anxin-security.exe' -Destination 'C:\Program Files\AnXinSecurity\anxin-security.exe' -Force
$swapped = Test-Path 'C:\Program Files\AnXinSecurity\anxin-security.exe'
"swapped=$swapped" | Add-Content $log
# inject headlessAutoTerminate into packaged app.json via the app's OWN authorized
# channel (--set-config): only anxin-security.exe passes FileProtect IsCallerAuthorized.
$exe = 'C:\Program Files\AnXinSecurity\anxin-security.exe'
$setOut = & $exe --set-config headlessAutoTerminate=true 2>&1 | Out-String
"set-config-out=$setOut" | Add-Content $log
# verify
$cfg = 'C:\Program Files\AnXinSecurity\_up_\config\app.json'
$utf8 = New-Object System.Text.UTF8Encoding($false)
if (Test-Path $cfg) {
    $verify = ([System.IO.File]::ReadAllText($cfg, $utf8) | ConvertFrom-Json).headlessAutoTerminate
    "headlessAutoTerminate=$verify" | Add-Content $log
} else {
    'NO CFG' | Add-Content $log
}
sc.exe start AnXinSecurityService 2>&1 | Out-Null
Start-Sleep -Seconds 8
(sc.exe query AnXinSecurityService 2>&1 | Out-String) -match 'RUNNING' | Out-String | Add-Content $log
"sys-deploy done" | Add-Content $log
'@
$sysScriptPath = "$vmTempDir\sys-deploy.ps1"
Invoke-Command -Session $s -ScriptBlock { param($p, $c) [System.IO.File]::WriteAllText($p, $c, (New-Object System.Text.UTF8Encoding($false))) } -ArgumentList $sysScriptPath, $sysScript
W "wrote sys-deploy.ps1 -> $sysScriptPath"

# 3. schedule + run as SYSTEM
Invoke-Command -Session $s -ScriptBlock {
    param($scriptPath)
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinDeployBuild' -InputObject $task -Force -ErrorAction SilentlyContinue | Out-Null
    Start-ScheduledTask -TaskName 'AnXinDeployBuild'
    'scheduled'
} -ArgumentList $sysScriptPath | ForEach-Object { W "  $_" }

# 4. wait + collect SYSTEM-side log
Start-Sleep -Seconds 30
$r = Invoke-Command -Session $s -ScriptBlock {
    if (Test-Path 'C:\Windows\Temp\anxin-deploy\sys-deploy.log') {
        Get-Content 'C:\Windows\Temp\anxin-deploy\sys-deploy.log'
    } else { 'NO SYS LOG' }
}
$r | ForEach-Object { W "  sys: $_" }

# 5. final verify from an interactive-context PS Direct call
$final = Invoke-Command -Session $s -ScriptBlock {
    $out = @()
    $exe = Get-Item 'C:\Program Files\AnXinSecurity\anxin-security.exe'
    $out += "exe bytes=$($exe.Length) modified=$($exe.LastWriteTime)"
    $svc = (sc.exe query AnXinSecurityService 2>&1 | Out-String)
    $out += ($svc -split "`r?`n" | Where-Object { $_ -match 'STATE' }) -join ''
    $cfg = 'C:\Program Files\AnXinSecurity\_up_\config\app.json'
    if (Test-Path $cfg) {
        $o = ([System.IO.File]::ReadAllText($cfg, (New-Object System.Text.UTF8Encoding($false))) | ConvertFrom-Json)
        $out += "headlessAutoTerminate=$($o.headlessAutoTerminate)"
    }
    $out
}
$final | ForEach-Object { W "  final: $_" }

Remove-PSSession $s
W "=== deploy-build done ==="
