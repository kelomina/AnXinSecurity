# install-test.ps1 - copy the NSIS installer to the "病毒测试" guest via PS Direct,
# run it silently with a completion poll (elevation spawns a new PID, so poll for
# ALL setup processes to exit + the service marker), then verify services/drivers/app.
# Host-side script; PS Direct does not need host elevation.
param(
    [Parameter(Mandatory=$true)][string]$InstallerPath,
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$GuestInstallPath = 'C:\Windows\Temp\AnXinSecurity-setup.exe',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-install-test.log',
    [int]$InstallTimeoutSec = 300
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== install-test @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath
if (-not (Test-Path $InstallerPath)) { W "ERROR: installer not found: $InstallerPath"; exit 1 }

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM $VmId not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started" }

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))

# connect (with retry window)
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VMId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

try { Copy-Item -Path $InstallerPath -Destination $GuestInstallPath -ToSession $s -Force; W "installer copied ($([IO.Path]::GetFileName($InstallerPath)))" }
catch { W "ERROR: copy to guest failed: $($_.Exception.Message)"; Remove-PSSession $s; exit 1 }

# process-name glob for the setup exe, e.g. "AnXinSecurity-1.0.0-setup"
# (process name = exe filename minus ".exe")
$procGlob = [IO.Path]::GetFileNameWithoutExtension($InstallerPath)

$out = Invoke-Command -Session $s -ScriptBlock {
    param($installer, $procGlob, $timeoutSec, $log)
    function GW([string]$m) { Add-Content -Path $log -Value $m }
    "=== GUEST-INSTALL @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
    "WHOAMI: $(whoami)"
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    "ELEVATED: $isAdmin"
    Get-Process -Name ('AnXinSecurity*') -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # launch the installer
    if ($isAdmin) {
        GW "launching directly (already elevated)"
        $p = Start-Process -FilePath $installer -ArgumentList '/S' -PassThru
    } else {
        GW "launching with -Verb RunAs (auto-elevate policy)"
        $p = Start-Process -FilePath $installer -ArgumentList '/S' -Verb RunAs -PassThru
    }
    "LAUNCHED-PID=$($p.Id)"

    # poll: no setup process remains AND the service was registered => install done
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $done = $false; $lastState = ''
    while ((Get-Date) -lt $deadline) {
        $procs = @(Get-Process -Name $procGlob -ErrorAction SilentlyContinue)
        $svc = (sc.exe query AnXinSecurityService 2>&1 | Out-String)
        $svcReg = $svc -match 'SERVICE_NAME'
        $svcState = (($svc -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ' '
        $lastState = "procs=$($procs.Count) svcReg=$svcReg $svcState"
        if ($procs.Count -eq 0 -and $svcReg) { $done = $true; break }
        Start-Sleep -Seconds 3
    }
    if ($done) { "INSTALL-DONE ($lastState)" } else { "INSTALL-TIMEOUT ($lastState)" }

    # give the installer's async steps (service start, UI spawn) a moment
    Start-Sleep -Seconds 8

    "--- services ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
        $reg = if ($q -match 'does not exist|1060') { 'NOT-REGISTERED' } else { 'registered' }
        "$svc : $reg $state"
    }
    "--- driver files ---"
    Get-ChildItem 'C:\Windows\System32\drivers\AnXin*' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name) $($_.Length) B mod $($_.LastWriteTime.ToString('MM-dd HH:mm'))" }
    "--- install dir ---"
    if (Test-Path 'C:\Program Files\AnXinSecurity') { Get-ChildItem 'C:\Program Files\AnXinSecurity' -Filter '*.exe' | ForEach-Object { "  $($_.Name) $($_.Length) B" } } else { "  no install dir" }
    "--- processes ---"
    Get-Process -Name 'anxin-security*' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name) pid=$($_.Id) path=$($_.Path)" }
    "--- recent System log driver/service events ---"
    Get-WinEvent -LogName System -MaxEvents 60 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 7036,7040,7000,7023,41,1001 } | Select-Object -First 15 TimeCreated, Id, @{n='m';e={$_.Message}} | ForEach-Object { "[$($_.TimeCreated.ToString('MM-dd HH:mm:ss'))] id=$($_.Id) " + (($_.m -split "`r?`n")[0]) }
    "=== GUEST-INSTALL DONE @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
} -ArgumentList $GuestInstallPath, $procGlob, $InstallTimeoutSec, 'C:\Windows\Temp\anxin-install-guest.log'

$out | ForEach-Object { W $_ }
# fetch the guest log back for the record
try {
    Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-install-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-install-guest.log' -Force
    W "guest log saved"
} catch {}
Remove-PSSession $s
W "=== install-test done ==="
