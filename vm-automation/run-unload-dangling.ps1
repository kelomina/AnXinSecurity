# Host runner: elevate unload-dangling-hive.ps1 (UAC prompt appears), read log.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-unload.log'
Remove-Item $log -ErrorAction SilentlyContinue
"launching ELEVATED unload-dangling (a UAC prompt will appear - please approve)..."
try {
    $p = Start-Process powershell.exe -Verb RunAs -PassThru -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','"E:\Project\HTML\AnXinSecurity\vm-automation\unload-dangling-hive.ps1"'
    "elevated process exit code: $($p.ExitCode)"
} catch {
    "elevated launch FAILED (UAC declined?): $($_.Exception.Message)"
}
"--- unload log ---"
if (Test-Path $log) { Get-Content $log } else { "no log file produced" }
