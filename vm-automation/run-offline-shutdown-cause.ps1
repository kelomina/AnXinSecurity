# Host runner: stop VM, run elevated offline-shutdown-cause (UAC prompt), read log.
$ErrorActionPreference = 'Continue'
$vmId = '7b66415c-52cb-468e-b9bd-368746f42863'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-shutdown-cause.log'

$vm = Get-VM -Id $vmId
"stopping VM (state=$($vm.State))..."
try { Stop-VM -VM $vm -Force -ErrorAction Stop } catch { "stop fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 3
"VM stopped: $((Get-VM -Id $vmId).State)"

Remove-Item $log -ErrorAction SilentlyContinue

"launching ELEVATED offline-shutdown-cause (a UAC prompt will appear - please approve)..."
try {
    $p = Start-Process powershell.exe -Verb RunAs -PassThru -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','"E:\Project\HTML\AnXinSecurity\vm-automation\offline-shutdown-cause.ps1"'
    "elevated process exit code: $($p.ExitCode)"
} catch {
    "elevated launch FAILED (UAC declined?): $($_.Exception.Message)"
}

"--- offline-shutdown-cause log ---"
if (Test-Path $log) { Get-Content $log } else { "no log file produced" }
