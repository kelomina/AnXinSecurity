# net-check.ps1 - verify VM outbound connectivity (controlled exfiltration topology).
# Confirms the VM keeps network access (not disconnected) and can reach the internet
# outbound while NAT blocks inbound. This matches user requirement: allow malware outbound.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-net-check.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== net-check @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started" }

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$r = Invoke-Command -Session $s -ScriptBlock {
    $out = @()
    $out += "--- adapter / ip / gateway / dns ---"
    $ad = Get-NetAdapter | Where-Object Status -eq 'Up'
    foreach ($a in $ad) {
        $out += "  ADAPTER: $($a.Name) [$($a.InterfaceDescription)] MAC=$($a.MacAddress)"
    }
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }
    foreach ($ip in $ips) { $out += "  IP: $($ip.IPAddress) on $($ip.InterfaceAlias)" }
    $gw = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
    foreach ($g in $gw) { $out += "  GW: $($g.NextHop) via $($g.InterfaceAlias)" }
    $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses }
    foreach ($d in $dns) { $out += "  DNS: $($d.InterfaceAlias) -> $($d.ServerAddresses -join ',')" }

    $out += "--- outbound reachability (real) ---"
    # 1) TCP connect to public host (443)
    $tcp = Test-NetConnection -ComputerName 'www.microsoft.com' -Port 443 -WarningAction SilentlyContinue
    $out += "  TCP 443 www.microsoft.com : $($tcp.TcpTestSucceeded) (RemoteAddress=$($tcp.RemoteAddress))"
    # 2) DNS resolution
    $dnsRes = Resolve-DnsName 'www.baidu.com' -ErrorAction SilentlyContinue | Select-Object -First 1
    $out += "  DNS www.baidu.com : $($dnsRes.IPAddress -join ',')"
    # 3) real HTTP fetch
    try {
        $resp = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $out += "  HTTP connecttest.txt : $($resp.StatusCode) body='$($resp.Content)'"
    } catch { $out += "  HTTP connecttest.txt : FAIL $($_.Exception.Message)" }
    # 4) default route reachability via ping (ICMP may be blocked, informational only)
    $ping = Test-Connection -ComputerName '223.5.5.5' -Count 2 -Quiet -ErrorAction SilentlyContinue
    $out += "  ICMP 223.5.5.5 : $ping"
    $out
}
$r | ForEach-Object { W $_ }

Remove-PSSession $s
W "=== net-check done ==="
