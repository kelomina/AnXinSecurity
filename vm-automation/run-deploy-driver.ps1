# Host runner: stop VM, run elevated deploy-driver (UAC prompt), read log.
# Usage: run-deploy-driver.ps1 [path-to-new-sys] [DiagFlags]
$ErrorActionPreference = 'Continue'
$vmId = '7b66415c-52cb-468e-b9bd-368746f42863'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-deploy-driver.log'
$newSys = 'E:\Project\HTML\AnXinSecurity\native\driver\build\x64\Release\AnXinProcProtect.sys'
$flags = 0
if ($args.Count -gt 0) { $newSys = $args[0] }
if ($args.Count -gt 1) { $flags = [int]$args[1] }
$argStr = """$newSys"" $flags"

$vm = Get-VM -Id $vmId
"stopping VM (state=$($vm.State))..."
try { Stop-VM -VM $vm -Force -ErrorAction Stop } catch { "stop fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 3
"VM stopped: $((Get-VM -Id $vmId).State)"

Remove-Item $log -ErrorAction SilentlyContinue

"launching ELEVATED deploy-driver (a UAC prompt will appear - please approve)..."
try {
    $p = Start-Process powershell.exe -Verb RunAs -PassThru -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','"E:\Project\HTML\AnXinSecurity\vm-automation\deploy-driver.ps1"',$argStr
    "elevated process exit code: $($p.ExitCode)"
} catch {
    "elevated launch FAILED (UAC declined?): $($_.Exception.Message)"
}

"--- deploy-driver log ---"
if (Test-Path $log) { Get-Content $log } else { "no log file produced" }
