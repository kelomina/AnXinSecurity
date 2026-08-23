# guest-cleanup.ps1 - clean up leftover spoof/probe files in the guest's Temp
# (copied powershell copies, probe outputs). Host-side; runs the guest-side part
# via Invoke-Command.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-guest-cleanup.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== guest-cleanup @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VMId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    '--- temp procs ---'
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like 'C:\Windows\Temp\*' } | ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        '  killed ' + $_.ProcessId
    }
    Start-Sleep 1
    '--- files ---'
    Get-ChildItem 'C:\Windows\Temp' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'anxin|probe|plain|cmd-copy|spoof' -and $_.Name -match '\.(exe|txt|out)$' } | ForEach-Object {
        try { Remove-Item $_.FullName -Force -ErrorAction Stop; '  deleted ' + $_.Name } catch { '  fail ' + $_.Name + ' :: ' + $_.Exception.Message }
    }
    '--- services ---'
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $st = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
        '  ' + $svc + ' : ' + $(if ($q -match 'does not exist|1060') { 'gone' } else { $st })
    }
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== guest-cleanup done ==="
