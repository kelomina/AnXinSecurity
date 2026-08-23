# antagonist-vmstate.ps1 - inspect current VM state: exe build, app.json config,
# service state, service log headless evidence. Host-side via PS Direct.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-vmstate.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== antagonist-vmstate @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

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

$out = Invoke-Command -Session $s -ScriptBlock {
    $res = @()
    $res += "=== VMSTATE ==="
    $exe = Get-Item 'C:\Program Files\AnXinSecurity\anxin-security.exe' -ErrorAction SilentlyContinue
    if ($exe) { $res += "exe bytes=$($exe.Length) modified=$($exe.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" } else { $res += 'NO EXE' }
    $cfg = 'C:\Program Files\AnXinSecurity\_up_\config\app.json'
    if (Test-Path $cfg) {
        $o = ([System.IO.File]::ReadAllText($cfg, (New-Object System.Text.UTF8Encoding($false))) | ConvertFrom-Json)
        $res += "headlessAutoTerminate=$($o.headlessAutoTerminate)"
    } else { $res += "NO CFG: $cfg" }
    $svc = (sc.exe query AnXinSecurityService 2>&1 | Out-String)
    $res += (($svc -split "`r?`n") | Where-Object { $_ -match 'STATE|SERVICE_NAME' }) -join ''
    # service log: look for headless evidence
    $logs = @()
    Get-ChildItem 'C:\Program Files\AnXinSecurity\logs','C:\Windows\Temp','C:\ProgramData\AnXinSecurity','C:\ProgramData\AnXinSecurity\logs' -Recurse -File -Filter '*.log' -ErrorAction SilentlyContinue | Select-Object -First 5 | ForEach-Object { $logs += "L: $($_.FullName) $($_.Length)B" }
    if ($logs.Count -eq 0) { $logs += 'NO LOG FILES FOUND' }
    $res += $logs
    $res += "=== VMSTATE END ==="
    $res
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== antagonist-vmstate done ==="
