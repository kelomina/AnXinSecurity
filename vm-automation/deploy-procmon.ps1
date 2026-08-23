# deploy-procmon.ps1 - deploy AnXinProcMon.sys to the "病毒测试" guest via PS Direct,
# register the kernel service (DEMAND_START, FltMgr dependency), write the minifilter
# Instances registry (altitude 380000), start the driver, then verify the device exists.
# Host-side script; PS Direct does not need host elevation.
param(
    [string]$SysPath = 'E:\Project\HTML\AnXinSecurity\native\proc_monitor\build\x64\Release\AnXinProcMon.sys',
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-deploy-procmon.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== deploy-procmon @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath
if (-not (Test-Path $SysPath)) { W "ERROR: sys not found: $SysPath"; exit 1 }
$size = (Get-Item $SysPath).Length
W "sys: $SysPath ($size B)"

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

try {
    Copy-Item -Path $SysPath -Destination 'C:\Windows\Temp\AnXinProcMon.sys' -ToSession $s -Force
    W "sys copied to guest"
} catch { W "ERROR: copy failed: $($_.Exception.Message)"; Remove-PSSession $s; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-DEPLOY @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

    # stop/delete any previous instance
    sc.exe stop AnXinProcMon 2>&1 | Out-Null
    sc.exe delete AnXinProcMon 2>&1 | Out-Null
    Start-Sleep -Seconds 2

    # copy into drivers dir
    Copy-Item 'C:\Windows\Temp\AnXinProcMon.sys' 'C:\Windows\System32\drivers\AnXinProcMon.sys' -Force
    GW "copied to drivers: $((Get-Item 'C:\Windows\System32\drivers\AnXinProcMon.sys').Length) B"

    # create the service (DEMAND_START, FltMgr dependency, Kernel driver)
    $sc = sc.exe create AnXinProcMon type= kernel start= demand error= normal binPath= "System32\drivers\AnXinProcMon.sys" depend= FltMgr 2>&1 | Out-String
    GW "sc create: $($sc.Trim())"

    # minifilter Instances registry (both Parameters\Instances and root Instances, like the INF AddReg)
    $svc = 'HKLM:\SYSTEM\CurrentControlSet\Services\AnXinProcMon'
    New-Item -Path "$svc\Parameters\Instances\AnXinProcMon Instance" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "$svc\Parameters\Instances" -Name 'DefaultInstance' -Value 'AnXinProcMon Instance' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "$svc\Parameters\Instances\AnXinProcMon Instance" -Name 'Altitude' -Value '380000' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "$svc\Parameters\Instances\AnXinProcMon Instance" -Name 'Flags' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path "$svc\Instances\AnXinProcMon Instance" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "$svc\Instances" -Name 'DefaultInstance' -Value 'AnXinProcMon Instance' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "$svc\Instances\AnXinProcMon Instance" -Name 'Altitude' -Value '380000' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "$svc\Instances\AnXinProcMon Instance" -Name 'Flags' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "$svc" -Name 'Group' -Value 'FSFilter Anti-Virus' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
    GW "Instances registry written (altitude 380000)"

    # start the driver
    $st = sc.exe start AnXinProcMon 2>&1 | Out-String
    GW "sc start: $($st.Trim())"
    Start-Sleep -Seconds 3
    $q = sc.exe query AnXinProcMon 2>&1 | Out-String
    GW "sc query: $($q.Trim())"

    # verify the device exists
    $dev = Test-Path '\\.\AnXinProcMon'
    GW "device \\.\AnXinProcMon exists: $dev"

    # dump driver load errors if any
    $errs = Get-WinEvent -LogName System -MaxEvents 80 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in 7000,7001,7023,41,1001 } | Select-Object -First 6
    foreach ($e in $errs) { GW "[$($e.TimeCreated.ToString('MM-dd HH:mm:ss'))] id=$($e.Id) " + (($e.Message -split "`r?`n")[0]) }
    "=== GUEST-DEPLOY DONE @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-procmon-guest.log'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-procmon-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-procmon-guest.log' -Force; W "guest log saved" } catch {}
Remove-PSSession $s
W "=== deploy-procmon done ==="
