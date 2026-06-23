param(
  [string]$VmName = "病毒测试",
  [string]$RelayRoot,
  [int]$PollSeconds = 2,
  [switch]$Once
)

# 这个脚本需要在“管理员 PowerShell / ADMIN_Saika PowerShell”里手动启动。
# Codex 不能直接拿到 Hyper-V 管理权限，所以它会把请求写到 logs/vm-relay/requests。
# 本脚本读取请求，用管理员权限执行有限的 Hyper-V / VM 调试动作，再把结果写回 responses 和 logs。

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptRoot

if ([string]::IsNullOrWhiteSpace($RelayRoot)) {
  $RelayRoot = Join-Path $RepoRoot "logs\vm-relay"
}

$RequestDir = Join-Path $RelayRoot "requests"
$ResponseDir = Join-Path $RelayRoot "responses"
$LogDir = Join-Path $RelayRoot "logs"
$ProcessedDir = Join-Path $RelayRoot "processed"
$FailedDir = Join-Path $RelayRoot "failed"
$RelayLog = Join-Path $LogDir "relay.log"

foreach ($dir in @($RelayRoot, $RequestDir, $ResponseDir, $LogDir, $ProcessedDir, $FailedDir)) {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

function Write-RelayLog {
  param([string]$Message)

  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
  Write-Host $line
  Add-Content -LiteralPath $RelayLog -Value $line -Encoding UTF8
}

function Test-PathStartsWith {
  param(
    [string]$Path,
    [string[]]$AllowedRoots
  )

  $resolved = [System.IO.Path]::GetFullPath($Path)
  foreach ($root in $AllowedRoots) {
    $resolvedRoot = [System.IO.Path]::GetFullPath($root)
    if (-not $resolvedRoot.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
      $resolvedRoot = $resolvedRoot + [System.IO.Path]::DirectorySeparatorChar
    }

    if ($resolved.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $resolved.Equals($resolvedRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar), [System.StringComparison]::OrdinalIgnoreCase)) {
      return $true
    }
  }

  return $false
}

function Convert-OutputToText {
  param($Output)

  if ($null -eq $Output) {
    return ""
  }

  return ($Output | Out-String -Width 240).TrimEnd()
}

function Invoke-GuestScript {
  param(
    [pscredential]$Credential,
    [string]$ScriptText,
    [int]$TimeoutSeconds = 900
  )

  if ([string]::IsNullOrWhiteSpace($ScriptText)) {
    throw "invoke_guest requires a non-empty 'script' field."
  }

  if ($TimeoutSeconds -lt 1) {
    throw "invoke_guest timeoutSeconds must be greater than 0."
  }

  $jobScript = {
    param(
      [string]$JobVmName,
      [pscredential]$JobCredential,
      [string]$InnerScriptText
    )

    Import-Module Hyper-V -ErrorAction SilentlyContinue

    $wrapper = {
      param([string]$NestedScriptText)

      $scriptBlock = [scriptblock]::Create($NestedScriptText)
      $captured = @()

      try {
        # Merge streams inside the guest. PowerShell Direct can otherwise surface native
        # stderr warnings as relay-level failures before Codex can inspect the result.
        $captured += & $scriptBlock *>&1
        $exitCode = if ($null -ne $global:LASTEXITCODE) { [int]$global:LASTEXITCODE } else { 0 }

        [pscustomobject]@{
          RelayGuestOk = $true
          ExitCode = $exitCode
          Output = ($captured | Out-String -Width 240).TrimEnd()
        }
      } catch {
        $captured += $_
        $exitCode = if ($null -ne $global:LASTEXITCODE) { [int]$global:LASTEXITCODE } else { $null }

        [pscustomobject]@{
          RelayGuestOk = $false
          ExitCode = $exitCode
          Output = ($captured | Out-String -Width 240).TrimEnd()
          Error = ($_ | Out-String -Width 240).TrimEnd()
        }
      }
    }

    Invoke-Command -VMName $JobVmName -Credential $JobCredential -ScriptBlock $wrapper -ArgumentList $InnerScriptText -ErrorAction Stop
  }

  $job = Start-Job -ScriptBlock $jobScript -ArgumentList $VmName, $Credential, $ScriptText
  try {
    if (-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) {
      Stop-Job -Job $job -ErrorAction SilentlyContinue
      throw "guest script timed out after $TimeoutSeconds seconds."
    }

    $jobOutput = Receive-Job -Job $job -ErrorAction Stop
  } finally {
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
  }

  $guestResult = @($jobOutput | Where-Object {
      $_.PSObject.Properties.Name -contains "RelayGuestOk"
    } | Select-Object -First 1)[0]
  if ($null -eq $guestResult) {
    throw "guest script returned no relay result."
  }

  if (-not $guestResult.RelayGuestOk) {
    $message = "guest script failed"
    if (-not [string]::IsNullOrWhiteSpace([string]$guestResult.Error)) {
      $message = [string]$guestResult.Error
    }
    throw $message
  }

  return [string]$guestResult.Output
}

function Remove-GuestPathIfExists {
  param(
    [pscredential]$Credential,
    [string]$GuestPath
  )

  $escapedPath = $GuestPath.Replace("'", "''")
  $script = @"
`$path = '$escapedPath'
if (Test-Path -LiteralPath `$path) {
  Remove-Item -LiteralPath `$path -Force
}
"@

  Invoke-GuestScript -Credential $Credential -ScriptText $script | Out-Null
}

function Invoke-RelayAction {
  param(
    [pscredential]$Credential,
    [pscustomobject]$Request
  )

  if (-not $Request.PSObject.Properties.Name.Contains("action")) {
    throw "Request is missing required field: action"
  }

  $action = [string]$Request.action

  switch ($action) {
    "get_vm_status" {
      $vm = Get-VM -Name $VmName
      $adapter = Get-VMNetworkAdapter -VMName $VmName
      $snapshots = Get-VMSnapshot -VMName $VmName -ErrorAction SilentlyContinue |
        Sort-Object CreationTime -Descending |
        Select-Object -First 5 Name, CreationTime, SnapshotType

      return [pscustomobject]@{
        vm = $vm | Select-Object Name, State, Generation, Version, ProcessorCount, MemoryAssigned, Uptime, Status
        adapter = $adapter | Select-Object VMName, Name, SwitchName, Status, MacAddress, IPAddresses
        snapshots = $snapshots
      }
    }

    "invoke_guest" {
      $timeoutSeconds = 900
      if ($Request.PSObject.Properties.Name.Contains("timeoutSeconds")) {
        $timeoutSeconds = [int]$Request.timeoutSeconds
      }

      $output = Invoke-GuestScript -Credential $Credential -ScriptText ([string]$Request.script) -TimeoutSeconds $timeoutSeconds
      return [pscustomobject]@{
        output = Convert-OutputToText $output
      }
    }

    "tail_guest_file" {
      if (-not $Request.PSObject.Properties.Name.Contains("path")) {
        throw "tail_guest_file requires field: path"
      }

      $tail = 120
      if ($Request.PSObject.Properties.Name.Contains("tail")) {
        $tail = [int]$Request.tail
      }

      $guestPath = [string]$Request.path
      $script = @"
`$path = '$($guestPath.Replace("'", "''"))'
if (Test-Path -LiteralPath `$path) {
  `$fs = [System.IO.File]::Open(`$path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    `$reader = New-Object System.IO.StreamReader(`$fs, [System.Text.Encoding]::UTF8, `$true, 4096)
    `$text = `$reader.ReadToEnd()
    `$lines = `$text -split "``r?``n"
    `$lines | Select-Object -Last $tail
  } finally {
    if (`$reader) { `$reader.Dispose() } else { `$fs.Dispose() }
  }
} else {
  "FILE_NOT_FOUND: `$path"
}
"@
      $output = Invoke-GuestScript -Credential $Credential -ScriptText $script -TimeoutSeconds 120
      return [pscustomobject]@{
        output = Convert-OutputToText $output
      }
    }

    "copy_to_guest" {
      if (-not $Request.PSObject.Properties.Name.Contains("sourcePath") -or
          -not $Request.PSObject.Properties.Name.Contains("destinationPath")) {
        throw "copy_to_guest requires fields: sourcePath, destinationPath"
      }

      $sourcePath = [string]$Request.sourcePath
      $destinationPath = [string]$Request.destinationPath

      if (-not (Test-Path -LiteralPath $sourcePath)) {
        throw "copy_to_guest source does not exist: $sourcePath"
      }

      if (-not (Test-PathStartsWith -Path $sourcePath -AllowedRoots @($RepoRoot, $RelayRoot))) {
        throw "copy_to_guest source must be inside repo or relay root: $sourcePath"
      }

      if (-not ($destinationPath.StartsWith("C:\Work\", [System.StringComparison]::OrdinalIgnoreCase) -or
                $destinationPath.Equals("C:\Work", [System.StringComparison]::OrdinalIgnoreCase))) {
        throw "copy_to_guest destination must be under C:\Work: $destinationPath"
      }

      Remove-GuestPathIfExists -Credential $Credential -GuestPath $destinationPath
      Copy-VMFile -Name $VmName -SourcePath $sourcePath -DestinationPath $destinationPath -FileSource Host -CreateFullPath
      return [pscustomobject]@{
        copied = $true
        sourcePath = $sourcePath
        destinationPath = $destinationPath
      }
    }

    "copy_from_guest" {
      if (-not $Request.PSObject.Properties.Name.Contains("sourcePath") -or
          -not $Request.PSObject.Properties.Name.Contains("destinationPath")) {
        throw "copy_from_guest requires fields: sourcePath, destinationPath"
      }

      $sourcePath = [string]$Request.sourcePath
      $destinationPath = [string]$Request.destinationPath
      $downloadRoot = Join-Path $RelayRoot "downloads"
      New-Item -ItemType Directory -Force -Path $downloadRoot | Out-Null

      if (-not (Test-PathStartsWith -Path $destinationPath -AllowedRoots @($downloadRoot))) {
        throw "copy_from_guest destination must be under relay downloads: $destinationPath"
      }

      Copy-VMFile -Name $VmName -SourcePath $sourcePath -DestinationPath $destinationPath -FileSource Guest -CreateFullPath
      return [pscustomobject]@{
        copied = $true
        sourcePath = $sourcePath
        destinationPath = $destinationPath
      }
    }

    "checkpoint" {
      $name = "AnXinSecurity-relay-$(Get-Date -Format yyyyMMdd-HHmmss)"
      if ($Request.PSObject.Properties.Name.Contains("snapshotName") -and
          -not [string]::IsNullOrWhiteSpace([string]$Request.snapshotName)) {
        $name = [string]$Request.snapshotName
      }

      Checkpoint-VM -Name $VmName -SnapshotName $name
      return [pscustomobject]@{
        snapshotName = $name
      }
    }

    "stop_relay" {
      $script:StopRequested = $true
      return [pscustomobject]@{
        stopRequested = $true
      }
    }

    default {
      throw "Unsupported action: $action"
    }
  }
}

function Complete-RequestFile {
  param(
    [System.IO.FileInfo]$File,
    [bool]$Succeeded
  )

  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $targetDir = if ($Succeeded) { $ProcessedDir } else { $FailedDir }
  $target = Join-Path $targetDir ("{0}-{1}" -f $stamp, $File.Name)
  Move-Item -LiteralPath $File.FullName -Destination $target -Force
}

Write-RelayLog "Starting VM admin relay. VM='$VmName', relayRoot='$RelayRoot'"
Write-RelayLog "Credential prompt is for the guest Windows account inside VM '$VmName'."
$GuestCredential = Get-Credential -Message "Enter guest Windows credentials for VM '$VmName'"

$script:StopRequested = $false

do {
  $files = Get-ChildItem -LiteralPath $RequestDir -Filter "*.json" -File -ErrorAction SilentlyContinue |
    Sort-Object Name

  foreach ($file in $files) {
    $id = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $requestLog = Join-Path $LogDir "$id.log"
    $responsePath = Join-Path $ResponseDir "$id.json"
    $startedAt = Get-Date

    Write-RelayLog "Processing request '$($file.Name)'"

    try {
      $raw = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
      $request = $raw | ConvertFrom-Json
      $result = Invoke-RelayAction -Credential $GuestCredential -Request $request
      $completedAt = Get-Date

      $response = [pscustomobject]@{
        id = $id
        ok = $true
        action = [string]$request.action
        startedAt = $startedAt.ToString("o")
        completedAt = $completedAt.ToString("o")
        result = $result
      }

      $response | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $responsePath -Encoding UTF8
      $response | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $requestLog -Encoding UTF8
      Complete-RequestFile -File $file -Succeeded $true
      Write-RelayLog "Completed request '$id'"
    } catch {
      $completedAt = Get-Date
      $errorText = $_ | Out-String

      $response = [pscustomobject]@{
        id = $id
        ok = $false
        startedAt = $startedAt.ToString("o")
        completedAt = $completedAt.ToString("o")
        error = [pscustomobject]@{
          message = $_.Exception.Message
          detail = $errorText.TrimEnd()
        }
      }

      $response | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $responsePath -Encoding UTF8
      $response | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $requestLog -Encoding UTF8
      Complete-RequestFile -File $file -Succeeded $false
      Write-RelayLog "Failed request '$id': $($_.Exception.Message)"
    }
  }

  if (-not $Once -and -not $script:StopRequested) {
    Start-Sleep -Seconds $PollSeconds
  }
} while (-not $Once -and -not $script:StopRequested)

Write-RelayLog "VM admin relay stopped."
