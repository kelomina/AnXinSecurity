# antagonist-prep.ps1 - prepare clean baseline WITH Defender exclusion, then snapshot it.
# 1) restore AntagonistReady_20260818  2) re-apply Defender C:\Samples exclusion + non-tamper prefs
# 3) verify services/drivers/rules  4) shutdown + standard checkpoint AntagonistReady_NoDefender_20260818  5) start VM
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-prep.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== prep @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
$VmName = '病毒测试'
$srcCp = 'AntagonistReady_20260818'
$dstCp = 'AntagonistReady_NoDefender_20260818'

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }

# 1) restore
if ($vm.State -ne 'Off') { Stop-VM -VM $vm -Force; W "VM stopped" }
Start-Sleep -Seconds 6
Restore-VMCheckpoint -VM $vm -Name $srcCp -Confirm:$false
W "checkpoint restored: $srcCp"
Start-VM -VM $vm
Start-Sleep -Seconds 25
W "VM started"

# 2) PS Direct + re-apply Defender settings
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(180); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 3
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$out = Invoke-Command -Session $s -ScriptBlock {
    "--- services/drivers ---"
    foreach ($svc in 'AnXinSecurityService','AnXinProcProtect','AnXinFileProtect','AnXinProcMon') {
        $q = sc.exe query $svc 2>&1 | Out-String
        "$svc = $(if ($q -match 'RUNNING') {'RUNNING'} else {'NOT-RUNNING'})"
    }
    "--- rules deployed (runtime config) ---"
    $rulesPath = 'C:\Program Files\AnXinSecurity\config\etw_match_rules.json'
    if (Test-Path $rulesPath) {
        $j = Get-Content $rulesPath -Raw | ConvertFrom-Json
        "rules file exists, rules count = $($j.rules.Count)"
    } else { "rules file NOT at $rulesPath" }
    "--- re-apply Defender settings ---"
    Set-MpPreference -ExclusionPath 'C:\Samples' -ErrorAction SilentlyContinue
    Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
    Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
    "exclusions now: $((Get-MpPreference).ExclusionPath -join ';')"
    "--- C:\Samples present? ---"
    "C:\Samples exists = $(Test-Path 'C:\Samples')"
}
$out | ForEach-Object { W $_; Write-Output $_ }

# 3) clean C:\Samples before snapshot
Invoke-Command -Session $s -ScriptBlock {
    if (Test-Path 'C:\Samples') { Remove-Item 'C:\Samples' -Recurse -Force -ErrorAction SilentlyContinue; 'C:\Samples removed' } else { 'C:\Samples clean' }
} | ForEach-Object { W $_ }
Remove-PSSession $s

# 4) shutdown + standard checkpoint
Stop-VM -VM $vm -Force
Start-Sleep -Seconds 6
if (Get-VMCheckpoint -VM $vm -Name $dstCp -ErrorAction SilentlyContinue) {
    Remove-VMCheckpoint -VM $vm -Name $dstCp -Confirm:$false -ErrorAction SilentlyContinue
}
Checkpoint-VM -VM $vm -SnapshotName $dstCp
W "checkpoint created: $dstCp"
Start-VM -VM $vm
W "VM started (clean baseline with Defender exclusion ready)"
"=== prep done ===" | Add-Content $LogPath
