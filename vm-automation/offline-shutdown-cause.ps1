# Elevated: mount broken child, get the 2-min-shutdown source (1074 events via Get-WinEvent),
# Tasks dir listing, Run/RunOnce keys, auto-start services. All-ASCII.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-shutdown-cause.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== shutdown-cause @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { W "ERROR: not elevated"; exit 1 }

$broken = Get-ChildItem 'D:\Virtual Hard Disks' -Filter '*31EECB48*' -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.avhdx' } | Select-Object -First 1
if (-not $broken) { W "ERROR: broken child not found"; exit 1 }
try { Mount-VHD -Path $broken.FullName -NoDriveLetter -ErrorAction Stop; W "mounted" } catch { W "mount fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 4
$disk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { ($_.Location -match '31EECB48') -or ($_.FriendlyName -match '31EECB48') } | Select-Object -First 1
if (-not $disk) { W "ERROR: disk not found"; exit 1 }
if ($disk.IsOffline) { try { Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction Stop; W "brought online" } catch {} }
$part = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 10GB } | Sort-Object Size -Descending | Select-Object -First 1
if (-not $part) { W "ERROR: no big partition"; exit 1 }
if (-not $part.DriveLetter) {
    $used = @(Get-Volume | Where-Object DriveLetter | ForEach-Object { $_.DriveLetter })
    $cand = @('X','V','W','Z') | Where-Object { $used -notcontains $_ } | Select-Object -First 1
    if (-not $cand) { $cand = 'X' }
    try { Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter $cand -ErrorAction Stop; W "assigned $cand" } catch {}
}
$part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
$letter = $part.DriveLetter
W "mount: $letter`:\"
$win = "$letter`:\Windows"

W "--- Tasks dir raw listing ---"
$tasksDir = "$win\System32\Tasks"
if (Test-Path $tasksDir) {
    $items = @(Get-ChildItem $tasksDir -Recurse -Force -ErrorAction SilentlyContinue)
    W "Tasks dir exists, item count = $($items.Count)"
    $items | Select-Object -First 40 | ForEach-Object { W "  taskitem: $($_.FullName.Substring($tasksDir.Length)) ($($_.GetType().Name))" }
    # also check the Tasks\Microsoft subfolders specifically
    Get-ChildItem $tasksDir -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        W "  taskfile: $($_.FullName.Substring($tasksDir.Length))"
    }
} else { W "no Tasks dir" }

W "--- 1074 shutdown events from System.evtx (Get-WinEvent) ---"
$evtx = "$win\System32\winevt\Logs\System.evtx"
if (Test-Path $evtx) {
    $evts = Get-WinEvent -Path $evtx -FilterXPath "*[System[(EventID=1074)]]" -MaxEvents 8 -ErrorAction SilentlyContinue
    if ($evts) {
        $evts | ForEach-Object {
            W "[$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] id=$($_.Id)"
            W "  $($_.Message)"
            W "  ---"
        }
    } else { W "no 1074 events found" }
} else { W "no System.evtx" }

W "--- bugcheck/restart events (1001/6008/41) ---"
if (Test-Path $evtx) {
    $evts = Get-WinEvent -Path $evtx -FilterXPath "*[System[(EventID=1001 or EventID=6008 or EventID=41)]]" -MaxEvents 8 -ErrorAction SilentlyContinue
    if ($evts) { $evts | ForEach-Object { W "[$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] id=$($_.Id): $($_.Message.Split("`n")[0])" } }
    else { W "no 1001/6008/41 events" }
}

W "--- SOFTWARE hive: Run/RunOnce + service names ---"
$cfg = "$letter`:\Windows\System32\config"
$ld = reg.exe load HKLM\RX_SOFTWARE "$cfg\SOFTWARE" 2>&1 | Out-String; W "load SOFTWARE: $($ld.Trim())"
if (Test-Path 'HKLM:\RX_SOFTWARE') {
    foreach ($k in 'Microsoft\Windows\CurrentVersion\Run','Microsoft\Windows\CurrentVersion\RunOnce','Microsoft\Windows\CurrentVersion\RunServices') {
        $key = "HKLM:\RX_SOFTWARE\$k"
        if (Test-Path $key) {
            W "--- Run key: $k ---"
            Get-ItemProperty $key | Format-List | Out-String -Stream | Where-Object { $_ -match ':' } | ForEach-Object { W "  $($_.Trim())" }
        } else { W "no Run key: $k" }
    }
    W "--- AnXinSoftware key ---"
    if (Test-Path 'HKLM:\RX_SOFTWARE\AnXinSecurity') { Get-ItemProperty 'HKLM:\RX_SOFTWARE\AnXinSecurity' | Format-List | Out-String -Stream | Where-Object { $_ -match ':' } | ForEach-Object { W "  $($_.Trim())" } } else { W "no AnXinSecurity SOFTWARE key" }
    $un = reg.exe unload HKLM\RX_SOFTWARE 2>&1 | Out-String; W "unload SOFTWARE: $($un.Trim())"
}

W "--- SYSTEM hive: auto-start (Start=2) services + all Start=1 boot drivers ---"
$ld = reg.exe load HKLM\RX_SYSTEM "$cfg\SYSTEM" 2>&1 | Out-String; W "load SYSTEM: $($ld.Trim())"
if (Test-Path 'HKLM:\RX_SYSTEM') {
    W "--- auto-start (Start=2) non-Microsoft services ---"
    Get-ChildItem 'HKLM:\RX_SYSTEM\ControlSet001\Services' -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.Start -eq 2 -and $_.PSChildName -notmatch '^(EventLog|Schedule|RpcSs|RpcEptMapper|DcomLaunch|PlugPlay|Power|SystemEventsBroker|LSM|BrokerInfrastructure|CoreMessagingRegistrar|TimeBrokerSvc|StateRepository|Winmgmt|W32Time|WSearch|wcncsvc|Wcmsvc|InstallService|wuauserv|WpnService|FontCache|FontCache3.0.0.0|WdiServiceHost|AeLookupSvc|CryptSvc|Dnscache|Dhcp|Netlogon|NlaSvc|nsi|SamSs|SENS|Spooler|stisvc|Themes|TrustedInstaller|UsoSvc|WbioSrvc|WinDefend|WlanSvc|Wlansvc|bthserv|BthAvctpSvc|DiagTrack|dmwappushservice|DusmSvc|gpsvc|IKEEXT|iphlpsvc|LanmanServer|LanmanWorkstation|LSM|MapsBroker|NcbService|NetSetupSvc|NfsClnt|PolicyAgent|ProfSvc|RasMan|RemoteRegistry|RetailDemo|RpcLocator|RsoPvd|SCardSvr|SCardEnum|SecurityHealthService|SensorDataService|SensorService|SensrSvc|SessionEnv|SstpSvc|StorSvc|SysMain|TabletInputService|TermService|TzSvc|UmRdpService|UserManager|UxSms|WdiSystemHost|WebClient|WinHttpAutoProxySvc|WMPNetworkSvc|WpcMonSvc|XblAuthManager|XblGameSave|XboxGipSvc|XboxNetApiSvc|XboxLiveAuthManager|XboxLiveGameSave|XboxNetApiSvc|cdpsvc|embeddedmode|fdPHost|hidserv|irmon|lmhosts|mpssvc|msiserver|NetTcpPortSharing|RasAuto|RasMan|RemoteAccess|seclogon|SysmonLog|TapiSrv|WAS|W3SVC|WerSvc|WMPNetworkSvc|wmiApSrv|WlanSvc|WudfSvc|BFE|CDPSvc|CDPUserSvc|CoreUIRegistrar|DeviceAssociationBrokerSvc|DeviceInstall|DevicePickerUserSvc|DevQueryBroker|DmEnrollmentSvc|DsmSvc|DsRoleSvc|Fax|FDResPub|FindNetworkPrinters|HomeGroupListener|HomeGroupProvider|PcaSvc|PerfHost|PhoneSvc|PrintNotify|PushToInstall|RetailDemo|RpcEptMapper|SgrmBroker|Spooler|stisvc|SysMain|Themes|WepSvc|WinDefend|WMPNetworkSvc|WpnUserService|wudfsvc)') {
            W "autostart: $($_.PSChildName) ImagePath=$($p.ImagePath)"
        }
    }
    W "--- boot-start (Start=1) drivers that mention anXin or unusual paths ---"
    Get-ChildItem 'HKLM:\RX_SYSTEM\ControlSet001\Services' -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.Start -eq 1) { W "bootstart: $($_.PSChildName) -> $($p.ImagePath)" }
    }
    $un = reg.exe unload HKLM\RX_SYSTEM 2>&1 | Out-String; W "unload SYSTEM: $($un.Trim())"
}

try { Dismount-VHD -Path $broken.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== shutdown-cause done ==="
