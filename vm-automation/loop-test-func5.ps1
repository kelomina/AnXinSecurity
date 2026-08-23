# loop-test-func5.ps1 - 查 SYSTEM (systemprofile) 用户的行为库 + ProcMon 设备连接。
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-loop-func5.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== loop-test-func5 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$s = $null; $deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== FUNC5 @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
    "--- systemprofile APPDATA AnXinSecurity ---"
    $sp = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity'
    if (Test-Path $sp) {
        Get-ChildItem $sp -Recurse -Depth 2 -ErrorAction SilentlyContinue | ForEach-Object {
            $rel = $_.FullName.Replace($sp, '')
            if ($_.PSIsContainer) { "  <dir> $rel" } else { $mt = $_.LastWriteTime.ToString('MM-dd HH:mm:ss'); "  $rel $($_.Length)B mtime=$mt" }
        }
    } else { "  NOT FOUND: $sp" }
    "--- ProgramData AnXinSecurity ---"
    $pd = "$env:ProgramData\AnXinSecurity"
    if (Test-Path $pd) {
        Get-ChildItem $pd -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {
            $rel = $_.FullName.Replace($pd, '')
            if ($_.PSIsContainer) { "  <dir> $rel" } else { $mt = $_.LastWriteTime.ToString('MM-dd HH:mm:ss'); "  $rel $($_.Length)B mtime=$mt" }
        }
    } else { "  NOT FOUND" }
    "=== FUNC5 DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== loop-test-func5 done ==="
