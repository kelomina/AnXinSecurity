# antagonist-etwcheck.ps1 - check ETW session liveness + service log in VM.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-etwcheck.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== etwcheck @ $(Get-Date -Format 'HH:mm:ss') ===" | Add-Content $LogPath
$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if ($vm.State -ne 'Running') { Start-VM -VM $vm; Start-Sleep -Seconds 20 }
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }

$r = Invoke-Command -Session $s -ScriptBlock {
    $out = @()
    $out += "--- logman ETW sessions ---"
    $lm = logman query -ets 2>&1 | Out-String
    $out += $lm
    $out += "--- service log tail (AnXinSecurityService) ---"
    # common service stderr redirect path
    $svc = (Get-CimInstance Win32_Service -Filter "Name='AnXinSecurityService'" -ErrorAction SilentlyContinue)
    if ($svc) {
        $out += "  PathName: $($svc.PathName)"
        $out += "  StartName: $($svc.StartName)"
    }
    # look for a log file under Program Files\AnXinSecurity
    foreach ($lg in @(
        'C:\Program Files\AnXinSecurity\*.log',
        'C:\Program Files\AnXinSecurity\logs\*.log',
        'C:\Program Files\AnXinSecurity\_up_\*.log',
        'C:\Windows\Temp\anxin*.log'
    )) {
        Get-ChildItem $lg -ErrorAction SilentlyContinue | ForEach-Object { $out += "  LOG: $($_.FullName) ($($_.Length) B)" }
    }
    # Event Log source
    $out += "--- event log (Application/System, AnXin) recent ---"
    try {
        Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=(Get-Date).AddMinutes(-30) } -MaxEvents 40 -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -like '*AnXin*' -or $_.Message -like '*AnXin*' } |
            Select-Object -First 10 | ForEach-Object { $out += "  [$($_.TimeCreated)] $($_.ProviderName): $($_.Message.Substring(0,[Math]::Min(160,$_.Message.Length)))" }
    } catch {}
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== etwcheck done ==="
