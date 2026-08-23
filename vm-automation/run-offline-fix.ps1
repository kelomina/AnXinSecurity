# Host runner: stop VM, run elevated offline-fix (UAC prompt appears), read log.
# Usage: run-offline-fix.ps1 [DiagFlags] [ServiceStart]
#   DiagFlags:    0=all features enabled (default), 12=ObCallbacks disabled
#   ServiceStart: 4=disabled (default), -1=skip service changes, 2=auto, 3=demand
$ErrorActionPreference = 'Continue'
$vmId = '7b66415c-52cb-468e-b9bd-368746f42863'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-offline-fix.log'
$flags = 0
$svcStart = 4
if ($args.Count -gt 0) { $flags = [int]$args[0] }
if ($args.Count -gt 1) { $svcStart = [int]$args[1] }
$argStr = "$flags $svcStart"

$vm = Get-VM -Id $vmId
"stopping VM (state=$($vm.State))..."
try { Stop-VM -VM $vm -Force -ErrorAction Stop } catch { "stop fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 3
"VM stopped: $((Get-VM -Id $vmId).State)"

Remove-Item $log -ErrorAction SilentlyContinue

"launching ELEVATED offline-fix (a UAC prompt will appear - please approve)..."
try {
    $p = Start-Process powershell.exe -Verb RunAs -PassThru -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','"E:\Project\HTML\AnXinSecurity\vm-automation\offline-fix.ps1"',"$argStr"
    "elevated process exit code: $($p.ExitCode)"
} catch {
    "elevated launch FAILED (UAC declined?): $($_.Exception.Message)"
}

"--- offline-fix log ---"
if (Test-Path $log) { Get-Content $log } else { "no log file produced" }
