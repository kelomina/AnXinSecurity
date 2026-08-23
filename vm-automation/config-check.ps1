# config-check.ps1 - locate and dump app.json in the VM (service load chain) and
# the anxin-security.exe path, so headlessAutoTerminate can be injected correctly.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-config-check.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== config-check @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

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

$r = Invoke-Command -Session $s -ScriptBlock {
    $out = @()
    # exe path (service binary)
    $out += "--- service binary ---"
    $svc = Get-CimInstance Win32_Service -Filter "Name='AnXinSecurityService'"
    if ($svc) { $out += "  exe=$($svc.PathName)" } else { $out += "  service not found" }
    # candidate app.json paths
    $out += "--- app.json candidates ---"
    $cands = @(
        'C:\Program Files\AnXinSecurity\_up_\config\app.json',
        'C:\Program Files\AnXinSecurity\resources\config\app.json',
        'C:\Program Files\AnXinSecurity\config\app.json',
        'C:\Windows\System32\config\app.json'
    )
    foreach ($p in $cands) {
        if (Test-Path $p) {
            $sz = (Get-Item $p).Length
            $out += "  EXISTS: $p ($sz B)"
        } else { $out += "  MISS  : $p" }
    }
    # dump the first existing packaged app.json (headlessAutoTerminate injection target)
    foreach ($p in $cands) {
        if (Test-Path $p) {
            $raw = [System.IO.File]::ReadAllText($p)
            $out += "===== $p ($($raw.Length) chars) ====="
            $out += $raw
            break
        }
    }
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== config-check done ==="
