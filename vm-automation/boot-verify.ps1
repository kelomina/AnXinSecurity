# boot-verify.ps1 - after the guest reboots, verify the FIXED drivers load at boot
# without a bugcheck, and the service + UI come up. Run on the host; no elevation needed.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-boot-verify.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== boot-verify @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started @ $(Get-Date -Format HH:mm:ss)" } else { W "VM already running" }

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(240); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VMId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 3
}
if (-not $s) { W "ERROR: PS Direct connect failed after reboot window"; exit 1 }
W "PS Direct connected @ $(Get-Date -Format HH:mm:ss)"

$out = Invoke-Command -Session $s -ScriptBlock {
    "BOOT-TIME: $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    "UPTIME-MIN: $([math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalMinutes, 2))"
    "--- AnXin services (expect RUNNING for all 4 after boot) ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
        $reg = if ($q -match 'does not exist|1060') { 'NOT-REGISTERED' } else { 'registered' }
        "$svc : $reg $state"
    }
    "--- driver files ---"
    Get-ChildItem 'C:\Windows\System32\drivers\AnXin*' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name) $($_.Length) B" }
    "--- bugcheck check (expect none since this boot) ---"
    $bt = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $ev = Get-WinEvent -LogName System -MaxEvents 400 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $bt -and $_.Id -in 41,1001,6008 }
    if ($ev) { $ev | ForEach-Object { "  BUGCHECK-CANDIDATE id=$($_.Id) @ $($_.TimeCreated): " + (($_.Message -split "`r?`n")[0]) } } else { "  no crash events since boot" }
    "--- driver load events (7036/7040) ---"
    Get-WinEvent -LogName System -MaxEvents 300 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $bt -and $_.Id -in 7036 } | Select-Object -First 12 TimeCreated, @{n='m';e={$_.Message}} | ForEach-Object { "[$($_.TimeCreated.ToString('MM-dd HH:mm:ss'))] " + (($_.m -split "`r?`n")[0]) }
    "--- app process ---"
    Get-Process -Name 'anxin-security*' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name) pid=$($_.Id)" }
    "--- service status detail ---"
    sc.exe queryex AnXinSecurityService | Select-String 'SERVICE_NAME|STATE|PID'
} -ErrorAction SilentlyContinue
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== boot-verify done ==="
