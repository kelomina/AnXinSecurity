# antagonist-setup.ps1 - Phase 2: deploy test-specific ETW block rules + record
# behavior DB baseline + confirm ProcMon activity. Host-side via PS Direct.
#
# Key constraint: FileProtect driver blocks writes to the install directory
# from non-SYSTEM processes. We use schtasks to run as SYSTEM for the copy.
#
# At the end of Phase 5, the original rules are restored via baseline restore.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-setup.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
$now0 = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
"=== antagonist-setup @ $now0 ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started" }

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VMId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

# ------- Step 1: verify current state -------
$info = Invoke-Command -Session $s -ScriptBlock {
    $exePath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AnXinSecurityService' -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    if ($exePath -match '"([^"]+)"') { $exePath = $matches[1] }
    $exeDir = [System.IO.Path]::GetDirectoryName($exePath)

    # Check which rule file paths exist and which are in the search order
    $cands = @(
        "$exeDir\config\etw_match_rules.json",
        "$exeDir\resources\config\etw_match_rules.json",
        "$exeDir\..\config\etw_match_rules.json",
        "$exeDir\_up_\config\etw_match_rules.json"
    )
    $results = @()
    foreach ($c in $cands) {
        if (Test-Path $c) {
            $sz = (Get-Item $c).Length
            $results += "EXISTS: $c ($sz B)"
        } else {
            $results += "MISS  : $c"
        }
    }
    @{
        ExePath = $exeDir
        Candidates = $results
        ExistingRulePath = ($cands | Where-Object { Test-Path $_ } | Select-Object -First 1)
        ProcMonStatus = (sc.exe query AnXinProcMon 2>&1 | Out-String)
        FileProtectStatus = (sc.exe query AnXinFileProtect 2>&1 | Out-String)
        ServiceStatus = (sc.exe query AnXinSecurityService 2>&1 | Out-String)
    }
}
W "Service exe dir: $($info.ExePath)"
$info.Candidates | ForEach-Object { W "  $_" }

# The target path for rules: use the FIRST existing candidate.
# The engine resolves 'config/etw_match_rules.json' relative to cwd (service cwd
# is the exe dir), so the actually-loaded file may live under _up_\config.
# Picking the first existing candidate guarantees we overwrite the file the
# engine actually reads.
$targetCfgPath = $info.ExistingRulePath
if (-not $targetCfgPath) { $targetCfgPath = "$($info.ExePath)\config\etw_match_rules.json" }
W "Target rule path: $targetCfgPath"

# ------- Step 2: write test rules to a temp location in VM -------
$testRules = @'
[
  {
    "ruleId": "registry_runkey_setvalue",
    "provider": "Registry",
    "op": "SetValue",
    "severity": 3,
    "threatType": "启动项持久化",
    "recommendAction": "alert",
    "description": "检测到进程写入自启动持久化位置（Run / RunOnce / Winlogon）。仅告警并记录，不自动挂起进程。",
    "targetPatterns": [
      "*\\currentversion\\run",
      "*\\currentversion\\runonce",
      "*\\currentversion\\runonceex",
      "*\\currentversion\\policies\\explorer\\run",
      "*\\currentversion\\winlogon"
    ]
  },
  {
    "ruleId": "temp_dropper_create",
    "provider": "File",
    "op": "Create",
    "severity": 2,
    "threatType": "临时目录可执行文件落地",
    "recommendAction": "alert",
    "description": "检测到在临时目录创建可执行或脚本文件，常见于落地后执行。安装器与更新程序也会命中，因此仅告警。",
    "targetPatterns": [
      "*\\temp\\*.exe",
      "*\\temp\\*.dll",
      "*\\temp\\*.scr",
      "*\\temp\\*.sys",
      "*\\temp\\*.ps1",
      "*\\temp\\*.bat",
      "*\\temp\\*.cmd",
      "*\\temp\\*.js",
      "*\\temp\\*.vbs"
    ]
  },
  {
    "ruleId": "temp_image_load",
    "provider": "Image",
    "op": "Load",
    "severity": 3,
    "threatType": "临时目录模块加载",
    "recommendAction": "alert",
    "description": "检测到进程加载来自临时目录的镜像模块，常见于落地后注入或旁加载。当前引擎不做签名判定，故不以【未签名】命名。",
    "targetPatterns": [
      "*\\temp\\*.dll",
      "*\\temp\\*.exe"
    ]
  },
  {
    "ruleId": "antagonist_runkey_persistence",
    "provider": "Registry",
    "op": "SetValue",
    "severity": 5,
    "threatType": "持久化-启动项",
    "recommendAction": "block",
    "description": "对抗测试：检测到进程在自启动位置写入注册表键值，可能为持久化行为。挂起进程。",
    "targetPatterns": [
      "*\\currentversion\\run",
      "*\\currentversion\\runonce"
    ]
  },
  {
    "ruleId": "antagonist_service_install",
    "provider": "Registry",
    "op": "SetValue",
    "severity": 5,
    "threatType": "持久化-服务安装",
    "recommendAction": "block",
    "description": "对抗测试：检测到进程在 Services 注册表路径写入，可能为服务持久化。挂起进程。",
    "targetPatterns": [
      "*\\currentcontrolset\\services\\*"
    ]
  },
  {
    "ruleId": "antagonist_temp_dropper_exec",
    "provider": "Image",
    "op": "Load",
    "severity": 5,
    "threatType": "恶意文件落地执行",
    "recommendAction": "block",
    "description": "对抗测试：检测到进程加载临时目录中的模块且随后有进程启动，常见于恶意文件释放后执行。挂起进程。",
    "targetPatterns": [
      "*\\temp\\*.exe",
      "*\\temp\\*.dll",
      "*\\temp\\*.scr"
    ],
    "required_ops": [
      { "provider": "File", "op": "Create" },
      { "provider": "Process", "op": "Start" }
    ]
  },
  {
    "ruleId": "antagonist_script_persistence",
    "provider": "Registry",
    "op": "SetValue",
    "severity": 5,
    "threatType": "脚本写入启动项",
    "recommendAction": "block",
    "description": "对抗测试：检测到脚本宿主（wscript/cscript/mshta）写入自启动注册表位置，疑似脚本型木马持久化。挂起进程。",
    "targetPatterns": [
      "*\\currentversion\\run",
      "*\\currentversion\\runonce"
    ],
    "required_ops": [
      { "provider": "Process", "op": "Start" }
    ]
  }
]
'@

# Write the test rules to a temp file on the host, then copy to VM temp
# Use .NET UTF-8 WITHOUT BOM (Set-Content -Encoding UTF8 writes BOM in PS5.1,
# which breaks serde_json on the Rust side; ANSI reading also garbles Chinese).
$localTestRules = "$env:TEMP\anxin_etw_test_rules.json"
[System.IO.File]::WriteAllText($localTestRules, $testRules, (New-Object System.Text.UTF8Encoding($false)))
W "Test rules written locally: $localTestRules"

# Copy to VM temp directory
$vmTempRules = "C:\Windows\Temp\anxin_etw_test_rules.json"
Copy-Item -Path $localTestRules -Destination $vmTempRules -ToSession $s -Force
W "Test rules copied to VM temp: $vmTempRules"

# ------- Step 3: back up original rules, then deploy test rules -------
# FileProtect blocks writes to the install dir from any process other than
# anxin-security.exe itself. So we deploy via:
#   anxin-security.exe --write-etw-rules <src>
# which runs as the signed/protected binary (passes IsCallerAuthorized) and
# writes to exe_dir/config/etw_match_rules.json -- the FIRST candidate in the
# engine's default_rule_config_paths(), so the service loads it on restart.
W "Backing up original rules and deploying test rules via --write-etw-rules..."

$backupResult = Invoke-Command -Session $s -ScriptBlock {
    param($vmTempRules, $targetCfgPath, $exeDir)

    $exe = "$exeDir\anxin-security.exe"

    # Back up existing rules if present (read-only, any user can read)
    $backupPath = "C:\Windows\Temp\etw_match_rules_backup.json"
    if (Test-Path $targetCfgPath) {
        Copy-Item -Path $targetCfgPath -Destination $backupPath -Force
        "BACKUP: $backupPath"
    } else {
        "NO-EXISTING-RULES: $targetCfgPath"
    }

    # Deploy via anxin-security.exe --write-etw-rules as SYSTEM (elevated +
    # trusted binary -> passes FileProtect IsCallerAuthorized).
    # NOTE: do NOT wrap in 'cmd.exe /c "..."' -- the inner quotes get eaten by
    # the task scheduler and the space in 'C:\Program Files' breaks the command.
    # Point ScheduledTaskAction -Execute directly at the exe (Task Scheduler
    # handles spaced paths correctly) and pass the argument separately.
    $action = New-ScheduledTaskAction -Execute "$exe" -Argument "--write-etw-rules `"$vmTempRules`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinDeployTestRules' -InputObject $task -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AnXinDeployTestRules'
    Start-Sleep -Seconds 6
    Unregister-ScheduledTask -TaskName 'AnXinDeployTestRules' -Confirm:$false -ErrorAction SilentlyContinue

    # Capture the exit code of the task (LastTaskResult) for diagnosis
    $taskInfo = Get-ScheduledTaskInfo -TaskName 'AnXinDeployTestRules' -ErrorAction SilentlyContinue
    if ($taskInfo) { "  CLI: LastTaskResult=$($taskInfo.LastTaskResult)" }

    # Verify --write-etw-rules wrote to exe_dir/config (NOT the _up_ path).
    # The subcommand resolves its destination as exe_dir\config\etw_match_rules.json,
    # which is also the FIRST candidate in the engine's default_rule_config_paths().
    $writePath = "$exeDir\config\etw_match_rules.json"
    if (Test-Path $writePath) {
        $sz = (Get-Item $writePath).Length
        $raw = [System.IO.File]::ReadAllText($writePath, (New-Object System.Text.UTF8Encoding($false)))
        try {
            $ruleCount = ($raw | ConvertFrom-Json | Measure-Object).Count
            "DEPLOYED: $writePath ($sz B, $ruleCount rules)"
        } catch {
            "DEPLOYED-BUT-INVALID-JSON: $writePath ($sz B) - $($_.Exception.Message)"
        }
    } else {
        "DEPLOY-FAILED: $writePath still missing"
    }
} -ArgumentList $vmTempRules, $targetCfgPath, $info.ExePath

$backupResult | ForEach-Object { W "  $_" }

# ------- Step 4: restart the service to reload rules -------
Invoke-Command -Session $s -ScriptBlock {
    sc.exe stop AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    sc.exe start AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 5
    $q = sc.exe query AnXinSecurityService 2>&1 | Out-String
    $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
    "SERVICE RESTART: $state"
} | ForEach-Object { W $_ }

# ------- Step 5: verify service + ProcMon are alive -------
$verify = Invoke-Command -Session $s -ScriptBlock {
    "--- services post-restart ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinProcMon','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
        "  $svc : $state"
    }
    "--- rule count ---"
    # Read as UTF-8 explicitly (Get-Content would use ANSI and garble Chinese JSON)
    $cfg = 'C:\Program Files\AnXinSecurity\config\etw_match_rules.json'
    if (Test-Path $cfg) {
        $raw = [System.IO.File]::ReadAllText($cfg, (New-Object System.Text.UTF8Encoding($false)))
        $n = ($raw | ConvertFrom-Json | Measure-Object).Count
        "  RULES: $n rules loaded from $cfg"
    } else {
        # fallback: check _up_ path
        $cfg2 = 'C:\Program Files\AnXinSecurity\_up_\config\etw_match_rules.json'
        if (Test-Path $cfg2) {
            $raw = [System.IO.File]::ReadAllText($cfg2, (New-Object System.Text.UTF8Encoding($false)))
            $n = ($raw | ConvertFrom-Json | Measure-Object).Count
            "  RULES: $n rules loaded (from $cfg2)"
        } else { "  RULES: no config file found" }
    }
    "--- ProcMon driver ---"
    fltmc filters 2>&1 | Select-String -Pattern 'AnXinProcMon' | ForEach-Object { "  $_" }
    "--- behavior db ---"
    $bd = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\data\behavior\anxin_etw_behavior.db'
    if (Test-Path $bd) { $sz = (Get-Item $bd).Length; "  DB: $sz B" } else { "  DB: not found" }
}
$verify | ForEach-Object { W $_ }

# ------- Step 6: record behavior DB baseline -------
# Service must be stopped to release the SQLite file lock, then copy via SYSTEM schtask
W "Recording behavior DB baseline (stopping service to release lock)..."
$baseline = Invoke-Command -Session $s -ScriptBlock {
    $bd = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\data\behavior\anxin_etw_behavior.db'
    $backupDb = "C:\Windows\Temp\anxin_etw_behavior_baseline.db"

    # Stop service to release DB lock
    sc.exe stop AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 5

    # Copy DB via SYSTEM schtask
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command ""Copy-Item -Path '$bd' -Destination '$backupDb' -Force"""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinCopyBaseline' -InputObject $task -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AnXinCopyBaseline'
    Start-Sleep -Seconds 5
    Unregister-ScheduledTask -TaskName 'AnXinCopyBaseline' -Confirm:$false -ErrorAction SilentlyContinue

    # Restart service
    sc.exe start AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 5

    $q = sc.exe query AnXinSecurityService 2>&1 | Out-String
    $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
    "SERVICE RESTART: $state"

    if (Test-Path $backupDb) {
        $sz = (Get-Item $backupDb).Length
        "BASELINE: $backupDb ($sz B)"
    } else {
        "BASELINE-FAILED"
    }
}
$baseline | ForEach-Object { W "  $_" }

# Copy the baseline DB from VM to host
$localDbDir = "E:\Project\HTML\AnXinSecurity\vm-automation\output"
New-Item -ItemType Directory -Path $localDbDir -Force | Out-Null
$localDbCopy = "$localDbDir\anxin_etw_behavior_baseline.db"
try {
    Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin_etw_behavior_baseline.db' -Destination $localDbCopy -Force
    $baseSize = (Get-Item $localDbCopy).Length
    W "Behavior DB baseline saved to host: $localDbCopy ($baseSize B)"
} catch {
    W "WARN: could not copy behavior DB from VM: $($_.Exception.Message)"
}

Remove-PSSession $s
W "=== antagonist-setup done ==="