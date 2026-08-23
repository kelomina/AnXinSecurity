# sample-draw.ps1 - Phase 1: randomly draw N PE + M script samples from the malware
# corpus (F:\私人\恶意\MB\unziped), compute SHA256 (read-only), and write a manifest CSV.
# Host-side ONLY: enumerates / hashes / copies - NEVER executes samples.
param(
    [string]$SampleRoot = 'F:\私人\恶意\MB\unziped',
    [string]$OutDir = 'E:\Project\HTML\AnXinSecurity\vm-automation\output',
    [int]$PECount = 42,
    [int]$ScriptCount = 8,
    [int]$Seed = 20260818,
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-sample-draw.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
$now0 = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
"=== sample-draw @ $now0 ===" | Add-Content $LogPath

if (-not (Test-Path $SampleRoot)) { W "ERROR: sample root not found: $SampleRoot"; exit 1 }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$PEext = @('.exe', '.dll')
$ScriptExt = @('.vbs', '.vbe', '.hta', '.js')

# --- enumerate lazily (1.1M files; avoid loading all into memory at once) ---
$stop = [Diagnostics.Stopwatch]::StartNew()
$peList = New-Object System.Collections.Generic.List[string]
$scriptList = New-Object System.Collections.Generic.List[string]
$counts = @{ total = 0; pe = 0; script = 0; other = 0 }

$enum = [System.IO.Directory]::EnumerateFiles($SampleRoot, '*.*', [System.IO.SearchOption]::AllDirectories)
foreach ($f in $enum) {
    $counts.total++
    $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
    if ($PEext -contains $ext) { $counts.pe++; $peList.Add($f) }
    elseif ($ScriptExt -contains $ext) { $counts.script++; $scriptList.Add($f) }
    else { $counts.other++ }
}
$stop.Stop()
W "enumerated total=$($counts.total) pe=$($counts.pe) script=$($counts.script) other=$($counts.other) in $([math]::Round($stop.Elapsed.TotalSeconds,1))s"

# guard: enough candidates
if ($peList.Count -lt $PECount) { W "ERROR: only $($peList.Count) PE candidates, need $PECount"; exit 1 }
if ($scriptList.Count -lt $ScriptCount) { W "WARN: only $($scriptList.Count) script candidates, need $ScriptCount" }

# --- random draw with fixed seed (reproducible) ---
$rng = New-Object System.Random($Seed)
function Draw-Count([int]$total, [int]$need) {
    # reservoir-free: shuffle indices via Random, take first $need
    $idx = 0..($total - 1)
    for ($i = 0; $i -lt $total; $i++) {
        $j = $rng.Next($i, $total)
        $t = $idx[$i]; $idx[$i] = $idx[$j]; $idx[$j] = $t
    }
    return ,$idx[0..($need - 1)]
}

$peIdx = Draw-Count $peList.Count $PECount
$scIdx = Draw-Count $scriptList.Count $ScriptCount

# --- build selected list (path, type, runcmd) ---
$selected = New-Object System.Collections.Generic.List[object]
$n = 0
foreach ($i in $peIdx) {
    $n++
    $p = $peList[$i]
    $type = [System.IO.Path]::GetExtension($p).ToLowerInvariant()
    $runcmd = if ($type -eq '.dll') { "rundll32.exe `"$p`",#1" } else { "`"$p`"" }
    $selected.Add([pscustomobject]@{ Seq = $n; Path = $p; Type = $type; RunCmd = $runcmd })
}
foreach ($i in $scIdx) {
    $n++
    $p = $scriptList[$i]
    $type = [System.IO.Path]::GetExtension($p).ToLowerInvariant()
    $host0 = switch ($type) { '.hta' { 'mshta.exe' } '.js' { 'wscript.exe' } default { 'wscript.exe' } }
    $runcmd = "$host0 `"$p`""
    $selected.Add([pscustomobject]@{ Seq = $n; Path = $p; Type = $type; RunCmd = $runcmd })
}
W "selected $($selected.Count) samples (PE=$PECount script=$ScriptCount)"

# --- SHA256 (read-only) ---
$stamp = Get-Date -Format 'yyyyMMdd'
$rows = New-Object System.Collections.Generic.List[object]
foreach ($s in $selected) {
    $hash = (Get-FileHash -LiteralPath $s.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    $size = (Get-Item -LiteralPath $s.Path -ErrorAction SilentlyContinue).Length
    $rows.Add([pscustomobject]@{
        Seq       = $s.Seq
        Sha256    = if ($hash) { $hash.ToLowerInvariant() } else { 'HASH-FAIL' }
        Type      = $s.Type
        Size      = $size
        OriginalPath = $s.Path
        RunCmd    = $s.RunCmd
        DrawnDate = $stamp
    })
    if (-not $hash) { W "WARN: hash failed for $($s.Path)" }
}
$csv = Join-Path $OutDir "sample-batch-$stamp.csv"
$rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
W "manifest written: $csv ($($rows.Count) rows)"
W "type distribution: $(($rows | Group-Object Type | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' ')"
W "=== sample-draw done ==="
