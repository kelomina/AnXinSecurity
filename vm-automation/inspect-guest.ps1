# inspect-guest.ps1 - after checkpoint restore, probe the guest's AnXin
# driver/service/software state so we know what deployment step is needed.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-inspect-guest.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== inspect-guest @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started (was $($vm.State))" }

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(180); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 3
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== GUEST-INSPECT @ $(Get-Date -Format HH:mm:ss) ==="
    "WHOAMI: $(whoami)"
    "OS: $((Get-CimInstance Win32_OperatingSystem).Caption) build=$((Get-CimInstance Win32_OperatingSystem).BuildNumber)"
    "--- AnXin driver files in System32\drivers ---"
    Get-ChildItem 'C:\Windows\System32\drivers\AnXin*' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name) $($_.Length) B mod $($_.LastWriteTime.ToString('MM-dd HH:mm'))" }
    "--- AnXin services ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
        $reg = if ($q -match 'does not exist|1060') { 'NOT-REGISTERED' } else { 'registered' }
        "  $svc : $reg $state"
    }
    "--- service ImagePath registry ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
        if (Test-Path $k) { $p = Get-ItemProperty $k -ErrorAction SilentlyContinue; "  $svc Start=$($p.Start) Type=$($p.Type) ImagePath=$($p.ImagePath)" }
        else { "  $svc no service key" }
    }
    "--- install dir ---"
    if (Test-Path 'C:\Program Files\AnXinSecurity') { Get-ChildItem 'C:\Program Files\AnXinSecurity' -Recurse -Depth 1 -ErrorAction SilentlyContinue | Select-Object -First 25 | ForEach-Object { "  $($_.FullName.Replace('C:\Program Files\AnXinSecurity','[INST]')) $($_.Length) B" } } else { "  no install dir" }
    "--- running anxin processes ---"
    Get-Process -Name 'anxin-security*' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name) pid=$($_.Id) path=$($_.Path)" }
    "=== GUEST-INSPECT DONE ==="
}

$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== inspect-guest done ==="
