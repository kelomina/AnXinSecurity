# dump-svc-keys.ps1 - dump all AnXin service keys' full value sets side by side
# to find why AnXinNetFilter is not recognized by SCM (1060). Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-svc-keys.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== dump-svc-keys @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== DUMP-SVC-KEYS @ $(Get-Date -Format HH:mm:ss) ==="
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
        "--- $svc ---"
        if (Test-Path $k) {
            $p = Get-ItemProperty $k
            $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $v = $_.Value
                if ($v -is [array]) { $v = $v -join ';' }
                "  $($_.Name) = $v"
            }
            "  subkeys: $((@(Get-ChildItem $k -ErrorAction SilentlyContinue)).Count)"
        } else { "  NO KEY" }
    }
    "--- SCM view via sc query type= driver (grep AnXin) ---"
    $all = & cmd.exe /c "sc query type= driver 2>&1" 2>&1 | Out-String
    ($all -split "`r?`n") | Where-Object { $_ -match 'AnXin' } | ForEach-Object { "  SCM: $_" }
    "=== DUMP-SVC-KEYS DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== dump-svc-keys done ==="
