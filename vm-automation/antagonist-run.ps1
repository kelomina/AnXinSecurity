# antagonist-run.ps1 - Phase 3: run ONE batch of adversarial tests in the VM.
# Per sample: reset interception state -> copy sample -> launch -> observe ->
# collect evidence (interception diagnostics / process state / network) ->
# preliminary verdict -> cleanup. Batch ends with behavior DB copied to host
# for weak-detection + ProcMon validation (done by antagonist-analyze-db.py).
#
# Security boundary: samples run ONLY inside the VM. Host only copies/hashes/
# orchestrates.
#
# Batch 1 should run with -SkipRestore (VM is already at AntagonistReady state).
# Later batches restore the AntagonistReady checkpoint first.
param(
    [Parameter(Mandatory=$true)][int]$Batch,
    [int]$BatchSize = 10,
    [string]$Manifest = 'E:\Project\HTML\AnXinSecurity\vm-automation\output\sample-batch-20260818.csv',
    [int]$ObserveSec = 30,
    [switch]$SkipRestore,
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$CheckpointName = 'AntagonistReady_20260818',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-run.log',
    [string]$OutDir = 'E:\Project\HTML\AnXinSecurity\vm-automation\output'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== antagonist-run batch=$Batch @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$rawJsonl = Join-Path $OutDir "batch-$Batch-raw.jsonl"
$resultCsv = Join-Path $OutDir "batch-$Batch-result.csv"
$rows = New-Object System.Collections.Generic.List[object]

# ---- load manifest ----
# NOTE: use $sampleList (NOT $manifest) — $Manifest is a [string]-typed param,
# so assigning Import-Csv to a same-named var would coerce the rows to a string.
$sampleList = Import-Csv -Path $Manifest
$total = $sampleList.Count
$first = (($Batch - 1) * $BatchSize) + 1
$last = [Math]::Min($Batch * $BatchSize, $total)
if ($first -gt $total) { W "ERROR: batch $Batch out of range (total $total)"; exit 1 }
$batchSamples = @($sampleList | Where-Object { [int]$_.Seq -ge $first -and [int]$_.Seq -le $last })
W "Batch ${Batch}: samples $first..$last ($($batchSamples.Count) items)"
W "  manifest total=$total rows, first Seq=[$($sampleList[0].Seq)] type=$($sampleList[0].Type) last=$last"

# ---- VM checkpoint restore (skip for batch 1 which is already test-ready) ----
if (-not $SkipRestore) {
    $vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
    if (-not $vm) { W "ERROR: VM not found"; exit 1 }
    if ($vm.State -ne 'Off') { Stop-VM -VM $vm -Force; W "VM stopped" }
    Start-Sleep -Seconds 5
    $cp = Get-VMCheckpoint -VM $vm -Name $CheckpointName -ErrorAction SilentlyContinue
    if (-not $cp) { W "ERROR: checkpoint '$CheckpointName' not found"; exit 1 }
    Restore-VMCheckpoint -VM $vm -Name $CheckpointName -Confirm:$false
    W "checkpoint restored: $CheckpointName"
    Start-VM -VM $vm
    Start-Sleep -Seconds 25
}

# ---- PS Direct connect ----
$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(180); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 3
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

# VM-side constants (verified by antagonist-verify.ps1)
$rtDir = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\runtime'
$diagFile = Join-Path $rtDir 'interception_diagnostics.jsonl'
$bdFile = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\data\behavior\anxin_etw_behavior.db'

# ---- helper: ensure service RUNNING ----
function Ensure-Service([System.Management.Automation.Runspaces.PSSession]$Session) {
    Invoke-Command -Session $Session -ScriptBlock {
        $q = sc.exe query AnXinSecurityService 2>&1 | Out-String
        if ($q -notmatch 'RUNNING') {
            sc.exe start AnXinSecurityService 2>&1 | Out-Null
            Start-Sleep -Seconds 5
        }
        (sc.exe query AnXinSecurityService 2>&1 | Out-String) -match 'RUNNING'
    }
}

# ---- helper: restart service (reset in-memory interception queue/state) ----
function Restart-Service([System.Management.Automation.Runspaces.PSSession]$Session) {
    Invoke-Command -Session $Session -ScriptBlock {
        sc.exe stop AnXinSecurityService 2>&1 | Out-Null
        Start-Sleep -Seconds 4
        sc.exe start AnXinSecurityService 2>&1 | Out-Null
        Start-Sleep -Seconds 6
        (sc.exe query AnXinSecurityService 2>&1 | Out-String) -match 'RUNNING'
    }
}

# ---- helper: gather sample process set (path under C:\Samples or descendant) ----
function Get-SampleProcessSet([System.Management.Automation.Runspaces.PSSession]$Session, [int]$LaunchedPid) {
    Invoke-Command -Session $Session -ScriptBlock {
        param($rootPid)
        $procs = Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine
        # seed: launched pid + any process whose executable path is under C:\Samples
        $set = [System.Collections.Generic.HashSet[int]]::new()
        if ($rootPid -gt 0) { [void]$set.Add($rootPid) }
        foreach ($p in $procs) {
            if ($p.ExecutablePath -and $p.ExecutablePath -like 'C:\Samples\*') { [void]$set.Add([int]$p.ProcessId) }
        }
        # walk descendants of any pid in set
        $changed = $true
        while ($changed) {
            $changed = $false
            foreach ($p in $procs) {
                if ($set.Contains([int]$p.ParentProcessId) -and -not $set.Contains([int]$p.ProcessId)) {
                    [void]$set.Add([int]$p.ProcessId); $changed = $true
                }
            }
        }
        ,@($procs | Where-Object { $set.Contains([int]$_.ProcessId) } | ForEach-Object {
            [pscustomobject]@{ Pid = [int]$_.ProcessId; Parent = [int]$_.ParentProcessId; Name = $_.Name; Path = $_.ExecutablePath; Cmd = $_.CommandLine }
        })
    } -ArgumentList $LaunchedPid
}

# ---- ensure test ready ----
if (-not (Ensure-Service $s)) { W "ERROR: service not RUNNING"; Remove-PSSession $s; exit 1 }
W "service RUNNING"

# clean stale C:\Samples from prior run
Invoke-Command -Session $s -ScriptBlock {
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like 'C:\Samples\*' -or $_.CommandLine -like '*C:\Samples\*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    if (Test-Path 'C:\Samples') { Remove-Item 'C:\Samples' -Recurse -Force -ErrorAction SilentlyContinue }
    'cleaned stale C:\Samples'
} | ForEach-Object { W "  $_" }

# ---- per-sample loop ----
$n = 0
foreach ($smpl in $batchSamples) {
    $n++
    $seq = [int]$smpl.Seq
    $hash = $smpl.Sha256
    $type = $smpl.Type.ToLowerInvariant()
    $srcPath = $smpl.OriginalPath
    $vmCase = "C:\Samples\case-$seq"
    $vmFile = "$vmCase\$hash$type"
    W "--- case $seq ($hash.Substring(0,16)... $type, $($smpl.Size) B) ---"

    # 1. reset interception state
    Restart-Service $s | ForEach-Object { W "  service reset: $_" }

    # 2. copy sample to VM
    try {
        Invoke-Command -Session $s -ScriptBlock { param($d) New-Item -ItemType Directory -Path $d -Force | Out-Null } -ArgumentList $vmCase
        Copy-Item -LiteralPath $srcPath -Destination $vmFile -ToSession $s -Force
        W "  copied -> $vmFile"
    } catch {
        $rec = [pscustomobject]@{ Seq=$seq; Hash=$hash; Type=$type; Verdict='COPY-FAIL'; Pids=''; Diag=''; Network=''; Note=$_.Exception.Message }
        $rows.Add($rec); $rec | ConvertTo-Json -Compress | Add-Content $rawJsonl
        W "  COPY-FAIL: $($_.Exception.Message)"
        continue
    }

    # 3. baseline: diagnostics line count
    $diagBase = Invoke-Command -Session $s -ScriptBlock { param($f) if (Test-Path $f) { (Get-Content $f | Measure-Object -Line).Lines } else { 0 } } -ArgumentList $diagFile

    # 4. launch
    $launch = Invoke-Command -Session $s -ScriptBlock {
        param($path, $ext)
        $p = $null
        switch ($ext) {
            '.dll'   { $p = Start-Process -FilePath 'rundll32.exe' -ArgumentList "`"$path`",#1" -PassThru -ErrorAction SilentlyContinue }
            '.hta'   { $p = Start-Process -FilePath 'mshta.exe'   -ArgumentList "`"$path`"" -PassThru -ErrorAction SilentlyContinue }
            '.js'    { $p = Start-Process -FilePath 'wscript.exe' -ArgumentList "`"$path`"" -PassThru -ErrorAction SilentlyContinue }
            '.vbs'   { $p = Start-Process -FilePath 'wscript.exe' -ArgumentList "`"$path`"" -PassThru -ErrorAction SilentlyContinue }
            '.vbe'   { $p = Start-Process -FilePath 'wscript.exe' -ArgumentList "`"$path`"" -PassThru -ErrorAction SilentlyContinue }
            default  { $p = Start-Process -FilePath $path -PassThru -ErrorAction SilentlyContinue }
        }
        if ($p) { @{ Pid = $p.Id; Name = $p.ProcessName } } else { $null }
    } -ArgumentList $vmFile, $type

    if (-not $launch -or -not $launch.Pid) {
        $rec = [pscustomobject]@{ Seq=$seq; Hash=$hash; Type=$type; Verdict='LAUNCH-FAIL'; Pids=''; Diag=''; Network=''; Note='Start-Process returned no PID' }
        $rows.Add($rec); $rec | ConvertTo-Json -Compress | Add-Content $rawJsonl
        W "  LAUNCH-FAIL"
        Invoke-Command -Session $s -ScriptBlock { param($d) if (Test-Path $d) { Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue } } -ArgumentList $vmCase
        continue
    }
    $launchedPid = [int]$launch.Pid
    W "  launched pid=$launchedPid ($($launch.Name))"

    # 5. observe
    Start-Sleep -Seconds $ObserveSec

    # 6. collect evidence
    $diagNew = Invoke-Command -Session $s -ScriptBlock {
        param($f, $baseLines)
        if (-not (Test-Path $f)) { return @() }
        $lines = Get-Content $f | Select-Object -Skip $baseLines
        $out = @()
        foreach ($ln in $lines) {
            try {
                $o = $ln | ConvertFrom-Json
                $out += [pscustomobject]@{
                    Timestamp = $o.timestamp
                    Stage     = $o.stage
                    Pid       = [int]($o.payload.pid)
                    ProcessName = $o.payload.processName
                    Threat    = $o.payload.threatType
                    RiskLevel = $o.payload.riskLevel
                    Reason    = $o.payload.reason
                    RuleId    = $o.payload.ruleId
                    FilePath  = $o.payload.filePath
                    Mode      = $o.payload.mode
                }
            } catch {}
        }
        ,$out
    } -ArgumentList $diagFile, $diagBase
    W "  new diagnostics lines: $($diagNew.Count)"

    $procSet = Get-SampleProcessSet $s $launchedPid
    $procSetPids = @($procSet | ForEach-Object { $_.Pid })
    W "  sample process set: $($procSetPids -join ',')"

    # frozen probe: sample alive but CPU frozen over 5s
    $frozen = $false
    $aliveNow = Invoke-Command -Session $s -ScriptBlock { param($pidArr) @(Get-Process -Id $pidArr -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }) } -ArgumentList $procSetPids
    if ($aliveNow.Count -gt 0) {
        $cpu1 = Invoke-Command -Session $s -ScriptBlock { param($pidArr) @(Get-Process -Id $pidArr -ErrorAction SilentlyContinue | ForEach-Object { $_.CPU }) } -ArgumentList $procSetPids
        Start-Sleep -Seconds 5
        $cpu2 = Invoke-Command -Session $s -ScriptBlock { param($pidArr) @(Get-Process -Id $pidArr -ErrorAction SilentlyContinue | ForEach-Object { $_.CPU }) } -ArgumentList $procSetPids
        if ($cpu1.Count -gt 0 -and $cpu1.Count -eq $cpu2.Count) {
            $sum1 = ($cpu1 | Measure-Object -Sum).Sum
            $sum2 = ($cpu2 | Measure-Object -Sum).Sum
            if ($sum2 -le $sum1) { $frozen = $true }
        }
    }
    W "  frozen probe: $frozen (alive=$($aliveNow.Count))"

    # network activity during window
    $net = @()
    $net = Invoke-Command -Session $s -ScriptBlock {
        param($pidArr)
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $pidArr -contains $_.OwningProcess } |
            ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort) (pid $($_.OwningProcess))" } |
            Select-Object -Unique
    } -ArgumentList $procSetPids

    # 7. verdict
    # STRONG requires corroborating interception diagnostics. A bare frozen
    # probe (alive but no CPU) with NO diagnostics is ambiguous (idle/hung
    # process) -> FROZEN-NO-EVIDENCE for manual review, not claimed as a hit.
    $strongDiag = @($diagNew | Where-Object {
        ($_.Stage -in @('interception_queue_push','interception_pre_suspended_entry','interception_queue_reject','etw_realtime_preblock_skipped')) -and
        ($procSetPids -contains $_.Pid -or ($_.FilePath -and $_.FilePath -like 'C:\Samples\*') -or ($_.ProcessName -eq $launch.Name))
    })
    $verdict = if ($strongDiag.Count -gt 0) { 'STRONG-INTERCEPT' }
               elseif ($frozen -and $aliveNow.Count -gt 0) { 'FROZEN-NO-EVIDENCE' }
               elseif ($launch.Name -and -not $aliveNow) { 'EXITED' }  # ran and finished on its own
               else { 'NOT-INTERCEPTED' }

    $diagSummary = @($strongDiag | ForEach-Object { "[$($_.Stage)] pid=$($_.Pid) $($_.ProcessName) threat=$($_.Threat) rule=$($_.RuleId) risk=$($_.RiskLevel) path=$($_.FilePath)" })
    if ($diagSummary.Count -eq 0) {
        $diagSummary = @($diagNew | Select-Object -First 5 | ForEach-Object { "[$($_.Stage)] pid=$($_.Pid) $($_.ProcessName) threat=$($_.Threat) rule=$($_.RuleId)" })
    }
    W "  verdict: $verdict"
    $diagSummary | ForEach-Object { W "    diag: $_" }
    $net | ForEach-Object { W "    net : $_" }

    $rec = [pscustomobject]@{
        Seq = $seq; Hash = $hash; Type = $type; Size = $smpl.Size
        Verdict = $verdict
        LaunchedPid = $launchedPid
        Pids = ($procSetPids -join ';')
        Frozen = $frozen
        DiagCount = $diagNew.Count
        Diag = ($diagSummary -join ' | ')
        Network = ($net -join ' | ')
        Note = ''
    }
    $rows.Add($rec)
    $rec | ConvertTo-Json -Compress | Add-Content $rawJsonl

    # 8. cleanup: kill sample processes + remove case dir + remove Run-key persistence
    # NOTE: use $p (not $pid) as loop variable — $PID is an automatic read-only var.
    Invoke-Command -Session $s -ScriptBlock {
        param($pidArr, $caseDir)
        foreach ($p in $pidArr) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 2
        # also kill any process whose cmdline references C:\Samples
        Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*C:\Samples\*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        if (Test-Path $caseDir) { Remove-Item $caseDir -Recurse -Force -ErrorAction SilentlyContinue }
        # scrub persistence pointing at C:\Samples
        foreach ($hive in 'HKCU:','HKLM:') {
            foreach ($keyPath in @("$hive\Software\Microsoft\Windows\CurrentVersion\Run",
                                   "$hive\Software\Microsoft\Windows\CurrentVersion\RunOnce")) {
                if (Test-Path $keyPath) {
                    $k = Get-Item $keyPath
                    foreach ($v in $k.GetValueNames()) {
                        $d = $k.GetValue($v)
                        if ($d -and ("$d" -like '*C:\Samples\*')) {
                            Remove-ItemProperty -Path $keyPath -Name $v -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        }
        'cleanup done'
    } -ArgumentList $procSetPids, $vmCase
    W "  cleanup done"
}

# ---- batch end: stop service, copy behavior DB to host, restart ----
W "--- batch end: copying behavior DB ---"
$dbLocal = Join-Path $OutDir "batch-$Batch-behavior.db"
# NOTE: $bdFile is a host-side var; must pass into remote session via -ArgumentList.
Invoke-Command -Session $s -ScriptBlock {
    param($bd)
    sc.exe stop AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 5
    $tmp = 'C:\Windows\Temp\batch-db.db'
    Copy-Item -Path $bd -Destination $tmp -Force
    sc.exe start AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 5
    'db staged'
} -ArgumentList $bdFile
try {
    Copy-Item -FromSession $s -Path 'C:\Windows\Temp\batch-db.db' -Destination $dbLocal -Force
    W "  behavior DB copied: $dbLocal"
} catch { W "  WARN: DB copy failed: $($_.Exception.Message)" }

Remove-PSSession $s

# ---- write batch result CSV ----
$rows | Export-Csv -Path $resultCsv -NoTypeInformation -Encoding UTF8
$summary = $rows | Group-Object Verdict | ForEach-Object { "$($_.Name)=$($_.Count)" }
W "Batch $Batch result: $($summary -join ' ')"
W "result CSV: $resultCsv"
W "=== antagonist-run batch=$Batch done ==="
