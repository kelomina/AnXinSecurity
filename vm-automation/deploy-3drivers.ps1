# deploy-3drivers.ps1 - deploy AnXinProcProtect + AnXinFileProtect + AnXinNetFilter
# to the guest (clean baseline) via PS Direct, for the P6 three-driver coexistence
# regression test. ProcMon is assumed already deployed.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-deploy-3drivers.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== deploy-3drivers @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$files = @{
    'AnXinProcProtect.sys' = 'E:\Project\HTML\AnXinSecurity\native\driver\build\x64\Release\AnXinProcProtect.sys';
    'AnXinFileProtect.sys' = 'E:\Project\HTML\AnXinSecurity\native\file_protect\build\x64\Release\AnXinFileProtect.sys';
    'AnXinNetFilter.sys'   = 'E:\Project\HTML\AnXinSecurity\native\net_filter\build\x64\Release\AnXinNetFilter.sys';
}
foreach ($k in $files.Keys) { if (-not (Test-Path $files[$k])) { W "ERROR: missing $k"; exit 1 } }

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

foreach ($k in $files.Keys) {
    try { Copy-Item -Path $files[$k] -Destination ("C:\Windows\Temp\" + $k) -ToSession $s -Force; W "copied $k" }
    catch { W "ERROR copy $k : $($_.Exception.Message)"; Remove-PSSession $s; exit 1 }
}

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-3DRIVERS @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

    # ProcProtect: plain kernel driver, SYSTEM_START semantics for prod but DEMAND here for test
    Copy-Item 'C:\Windows\Temp\AnXinProcProtect.sys' 'C:\Windows\System32\drivers\' -Force
    sc.exe create AnXinProcProtect type= kernel start= demand error= normal binPath= "\SystemRoot\System32\drivers\AnXinProcProtect.sys" 2>&1 | Out-Null
    $p1 = sc.exe start AnXinProcProtect 2>&1 | Out-String
    GW "ProcProtect: $($p1.Trim())"
    Start-Sleep -Seconds 2

    # FileProtect: minifilter 328800 + Instances registry
    Copy-Item 'C:\Windows\Temp\AnXinFileProtect.sys' 'C:\Windows\System32\drivers\' -Force
    sc.exe create AnXinFileProtect type= kernel start= demand error= normal binPath= "\SystemRoot\System32\drivers\AnXinFileProtect.sys" depend= FltMgr 2>&1 | Out-Null
    $fp = 'HKLM:\SYSTEM\CurrentControlSet\Services\AnXinFileProtect'
    New-Item -Path "$fp\Parameters\Instances\AnXinFileProtect Instance" -Force | Out-Null
    New-ItemProperty -Path "$fp\Parameters\Instances" -Name 'DefaultInstance' -Value 'AnXinFileProtect Instance' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$fp\Parameters\Instances\AnXinFileProtect Instance" -Name 'Altitude' -Value '328800' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$fp\Parameters\Instances\AnXinFileProtect Instance" -Name 'Flags' -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$fp" -Name 'Group' -Value 'FSFilter Anti-Virus' -PropertyType String -Force | Out-Null
    $p2 = sc.exe start AnXinFileProtect 2>&1 | Out-String
    GW "FileProtect: $($p2.Trim())"
    Start-Sleep -Seconds 2

    # NetFilter: WFP callout, depends on Tcpip
    Copy-Item 'C:\Windows\Temp\AnXinNetFilter.sys' 'C:\Windows\System32\drivers\' -Force
    sc.exe create AnXinNetFilter type= kernel start= demand error= normal binPath= "\SystemRoot\System32\drivers\AnXinNetFilter.sys" depend= Tcpip 2>&1 | Out-Null
    $p3 = sc.exe start AnXinNetFilter 2>&1 | Out-String
    GW "NetFilter: $($p3.Trim())"
    Start-Sleep -Seconds 2

    "--- all services ---"
    foreach ($svc in 'AnXinProcMon','AnXinProcProtect','AnXinFileProtect','AnXinNetFilter') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ' '
        GW "$svc : $state"
    }
    "--- fltmc filters ---"
    fltmc filters 2>&1 | Out-String | ForEach-Object { GW $_ }
    "--- errors ---"
    Get-WinEvent -LogName System -MaxEvents 40 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 7000,7001,7023,41,1001 } | Select-Object -First 8 TimeCreated, Id, @{n='m';e={($_.Message -split "`r?`n")[0]}} | ForEach-Object { GW "[$($_.TimeCreated.ToString('MM-dd HH:mm:ss'))] id=$($_.Id) $($_.m)" }
    "=== GUEST-3DRIVERS DONE @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-3drivers-guest.log'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-3drivers-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-3drivers-guest.log' -Force; W "guest log saved" } catch {}
Remove-PSSession $s
W "=== deploy-3drivers done ==="
