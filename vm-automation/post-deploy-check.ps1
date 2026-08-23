# post-deploy-check.ps1 - inspect actual state after the deploy attempt:
# exe hash/size, app.json content, FileProtect protection entries, sys-deploy log.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-post-deploy-check.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== post-deploy-check @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

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
    $out += '--- exe hashes ---'
    foreach ($p in @('C:\Program Files\AnXinSecurity\anxin-security.exe','C:\Windows\Temp\anxin-deploy\anxin-security.exe')) {
        if (Test-Path $p) {
            $h = (Get-FileHash $p -Algorithm SHA256).Hash
            $sz = (Get-Item $p).Length
            $out += "  $p  size=$sz  sha256=$($h.Substring(0,16))..."
        } else { $out += "  MISS $p" }
    }
    $out += '--- app.json content ---'
    $cfg = 'C:\Program Files\AnXinSecurity\_up_\config\app.json'
    if (Test-Path $cfg) {
        $raw = [System.IO.File]::ReadAllText($cfg, (New-Object System.Text.UTF8Encoding($false)))
        $out += "  has headlessAutoTerminate: $($raw -match 'headlessAutoTerminate')"
        $out += "  file size: $((Get-Item $cfg).Length)"
    }
    $out += '--- FileProtect protected paths (config) ---'
    $fpCfg = 'C:\Program Files\AnXinSecurity\config\fileprotect_rules.json'
    if (Test-Path $fpCfg) {
        $raw = [System.IO.File]::ReadAllText($fpCfg, (New-Object System.Text.UTF8Encoding($false)))
        $out += ($raw.Substring(0, [Math]::Min(2000, $raw.Length)))
    } else { $out += '  no fileprotect_rules.json at that path' }
    $out += '--- sys-deploy.log ---'
    $sl = 'C:\Windows\Temp\anxin-deploy\sys-deploy.log'
    if (Test-Path $sl) { $out += (Get-Content $sl) } else { $out += '  MISS' }
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== post-deploy-check done ==="
