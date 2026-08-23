# Host watcher: start VM (if not running) and watch for the boot outcome.
# Reports: OS-started / BSOD (crash) / graceful guest shutdown, with uptime at each.
# Criterion for the boot-safety test: NO 18590/18591 (crash/BSOD) events.
$ErrorActionPreference = 'Continue'
$vmId = '7b66415c-52cb-468e-b9bd-368746f42863'
$watchSeconds = 210
if ($args.Count -gt 0) { $watchSeconds = [int]$args[0] }

$vm = Get-VM -Id $vmId
if ($vm.State -ne 'Running') {
    Start-VM -VM $vm -ErrorAction Stop
    "VM started at $(Get-Date -Format HH:mm:ss)"
    Start-Sleep -Seconds 5
}

$startTime = Get-Date
$deadline = (Get-Date).AddSeconds($watchSeconds)
$crashSeen = $false
$shutdownSeen = $false

while ((Get-Date) -lt $deadline) {
    $vm = Get-VM -Id $vmId
    if ($vm.State -ne 'Running') {
        "STATE $($vm.State) at uptime $([math]::Round($vm.Uptime.TotalSeconds))s (boot $(Get-Date -Format HH:mm:ss))"
        break
    }
    $uptime = [math]::Round((Get-Date - $startTime).TotalSeconds)

    # check for crash/shutdown events since boot
    $evts = Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Worker-Admin' -MaxEvents 30 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime -and $_.Id -in 18508,18509,18590,18591,18601 }
    foreach ($e in $evts) {
        if ($e.Id -in 18590,18591) { $crashSeen = $true; "CRASH/BSOD id=$($e.Id) at boot+$uptime s [$($e.TimeCreated.ToString('HH:mm:ss'))]" }
        if ($e.Id -eq 18508) { $shutdownSeen = $true; "GUEST SHUTDOWN (18508) at boot+$uptime s [$($e.TimeCreated.ToString('HH:mm:ss'))]" }
        if ($e.Id -eq 18601) { "OS STARTED (18601) at boot+$uptime s [$($e.TimeCreated.ToString('HH:mm:ss'))]" }
    }

    if ($vm.Uptime.TotalSeconds -gt 180) {
        "STABLE: guest up > 180s (uptime=$([math]::Round($vm.Uptime.TotalSeconds))s) state=$($vm.State)"
        break
    }
    Start-Sleep -Seconds 5
}

"--- summary @ $(Get-Date -Format HH:mm:ss) ---"
"state=$((Get-VM -Id $vmId).State) uptime=$([math]::Round((Get-VM -Id $vmId).Uptime.TotalSeconds))s"
"crashSeen=$crashSeen  shutdownSeen=$shutdownSeen"
if (-not $crashSeen -and -not $shutdownSeen) { "RESULT: clean stable boot (no crash, no shutdown)" }
elseif ($crashSeen) { "RESULT: BSOD/CRASH detected - fix did NOT prevent it" }
else { "RESULT: no crash but guest shut itself down (18508)" }
