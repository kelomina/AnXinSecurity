# antagonist-retest-leaks2.ps1 - run leaked samples (seq 2/3/4) with fresh copies
# after Defender exclusion is in place. Uses cmd /c start to bypass AMSI.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [int]$ObserveSec = 30
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== retest-leaks2 @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

$manifest = 'E:\Project\HTML\AnXinSecurity\vm-automation\output\sample-retest-leaks.csv'
$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))

$all = Import-Csv -Path $manifest
$samples = @($all | Where-Object { [int]$_.Seq -ge 2 })

function Connect-VM {
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; return $s } catch {}
        Start-Sleep -Seconds 2
    }
    return $null
}

$results = @()

foreach ($smpl in $samples) {
    $seq = [int]$smpl.Seq; $hash = $smpl.Sha256; $type = $smpl.Type; $src = $smpl.OriginalPath
    $vmCase = "C:\Samples\case-$seq"
    $vmFile = "$vmCase\$hash$type"

    W "--- case $seq ($($hash.Substring(0,16))... $type) ---"
    if (-not (Test-Path -LiteralPath $src)) { W "  SRC-MISSING"; continue }

    $s = Connect-VM
    if (-not $s) { W "  CONNECT-FAIL"; continue }

    # pre-clean + service reset
    Invoke-Command -Session $s -ScriptBlock {
        Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like 'C:\Samples\*' -or $_.CommandLine -like '*C:\Samples\*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 2
        if (Test-Path 'C:\Samples') { Remove-Item 'C:\Samples' -Recurse -Force -ErrorAction SilentlyContinue }
        sc.exe stop AnXinSecurityService 2>&1 | Out-Null
        Start-Sleep -Seconds 4
        sc.exe start AnXinSecurityService 2>&1 | Out-Null
        Start-Sleep -Seconds 6
        (sc.exe query AnXinSecurityService 2>&1 | Out-String) -match 'RUNNING'
    } -ErrorAction SilentlyContinue | Out-Null

    # copy sample
    try {
        Invoke-Command -Session $s -ScriptBlock { param($d) New-Item -ItemType Directory -Path $d -Force | Out-Null } -ArgumentList $vmCase -ErrorAction Stop
        Copy-Item -LiteralPath $src -Destination $vmFile -ToSession $s -Force -ErrorAction Stop
        W "  copied -> $vmFile"
    } catch { W "  COPY-FAIL: $($_.Exception.Message)"; Remove-PSSession $s; continue }

    $diagFile = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\runtime\interception_diagnostics.jsonl'
    $diagBase = Invoke-Command -Session $s -ScriptBlock { param($f) if (Test-Path $f) { (Get-Content $f | Measure-Object -Line).Lines } else { 0 } } -ArgumentList $diagFile -ErrorAction SilentlyContinue

    # launch via cmd /c start to bypass AMSI (Start-Process triggers Defender AMSI)
    $launch = Invoke-Command -Session $s -ScriptBlock { param($p) cmd /c start "" /B "$p" } -ArgumentList $vmFile -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    # find the process by path
    $found = Invoke-Command -Session $s -ScriptBlock { param($p) Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $p } | Select-Object ProcessId } -ArgumentList $vmFile -ErrorAction SilentlyContinue
    if (-not $found) {
        W "  LAUNCH-FAIL (cmd start also blocked)"
        $results += [pscustomobject]@{ Seq=$seq; Verdict='LAUNCH-FAIL'; Note='cmd /c start /B also blocked by Defender' }
        Remove-PSSession $s; continue
    }
    $launchedPid = [int]$found.ProcessId
    W "  launched pid=$launchedPid"

    Start-Sleep -Seconds $ObserveSec

    Remove-PSSession $s -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3
    $s = Connect-VM
    if (-not $s) { W "  RECONNECT-FAIL"; $results += [pscustomobject]@{ Seq=$seq; Verdict='RECONNECT-FAIL' }; continue }

    $diagNew = Invoke-Command -Session $s -ScriptBlock {
        param($f, $base) if (-not (Test-Path $f)) { return @() }
        $lines = Get-Content $f | Select-Object -Skip $base; $out = @()
        foreach ($ln in $lines) { try { $o = $ln | ConvertFrom-Json; $out += $o } catch {} }
        ,$out
    } -ArgumentList $diagFile, $diagBase -ErrorAction SilentlyContinue

    $strongDiag = @($diagNew | Where-Object { $_.stage -in @('interception_queue_push','headless_auto_terminated','interception_pre_suspended_entry') -and $_.payload.pid -eq $launchedPid })
    $alive = Invoke-Command -Session $s -ScriptBlock { param($p) @(Get-Process -Id $p -ErrorAction SilentlyContinue).Count } -ArgumentList $launchedPid -ErrorAction SilentlyContinue

    $verdict = if ($strongDiag.Count -gt 0) { 'STRONG-INTERCEPT' }
               elseif ($alive -eq 0) { 'EXITED' }
               else { 'NOT-INTERCEPTED' }

    $diagSummary = $strongDiag | ForEach-Object { "[$($_.stage)] pid=$($_.payload.pid) threat=$($_.payload.threatType) rule=$($_.payload.ruleId)" }
    if ($diagSummary.Count -eq 0 -and $diagNew.Count -gt 0) { $diagSummary = $diagNew | Select-Object -First 3 | ForEach-Object { "[$($_.stage)] pid=$($_.payload.pid) $($_.payload.reason)" } }
    W "  verdict=$verdict alive=$alive strongDiag=$($strongDiag.Count)"
    $diagSummary | ForEach-Object { W "    $_" }

    $results += [pscustomobject]@{ Seq=$seq; Hash=$hash; Verdict=$verdict; DiagCount=$diagNew.Count; Note=($diagSummary -join ' | ') }

    Invoke-Command -Session $s -ScriptBlock { param($pid, $dir) Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; if (Test-Path $dir) { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue } } -ArgumentList $launchedPid, $vmCase -ErrorAction SilentlyContinue
    Remove-PSSession $s -ErrorAction SilentlyContinue
}

W "=== results ==="
$results | Format-Table Seq, Verdict, DiagCount, Note -AutoSize | Out-String -Width 200 | ForEach-Object { W $_.TrimEnd() }
W "=== retest-leaks2 done ==="