# diag-port3.ps1 - 枚举对象管理器命名空间，定位 AnXinFileProtectPort 实际对象路径。Host-side.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port3.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-port3 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; Start-Sleep -Seconds 15 }

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$cs = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

public class ObEnum {
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES {
        public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
        public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_DIRECTORY_INFORMATION {
        public UNICODE_STRING Name; public UNICODE_STRING TypeName;
    }
    [DllImport("ntdll.dll")]
    static extern int NtQueryDirectoryObject(IntPtr DirectoryHandle, IntPtr Buffer, int BufferLength,
        bool ReturnSingleEntry, bool RestartScan, ref uint Context, out uint ReturnLength);
    [DllImport("ntdll.dll")]
    static extern int NtOpenDirectoryObject(out IntPtr Handle, uint DesiredAccess, ref OBJECT_ATTRIBUTES Oa);
    [DllImport("ntdll.dll")]
    static extern void RtlInitUnicodeString(ref UNICODE_STRING Dest, [MarshalAs(UnmanagedType.LPWStr)] string Source);
    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr Handle);

    public static List<string> Enumerate(string dir) {
        var results = new List<string>();
        IntPtr dirHandle;
        var name = new UNICODE_STRING();
        RtlInitUnicodeString(ref name, dir);
        var oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        var namePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(name, namePtr, false);
        oa.ObjectName = namePtr;
        oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
        int st = NtOpenDirectoryObject(out dirHandle, 0x0001, ref oa); // DIRECTORY_QUERY
        Marshal.FreeHGlobal(namePtr);
        if (st != 0) { results.Add("OPEN_FAILED 0x" + st.ToString("X8")); return results; }
        int bufSize = 262144;
        IntPtr buf = Marshal.AllocHGlobal(bufSize);
        uint ctx = 0, retLen = 0;
        int entrySize = Marshal.SizeOf(typeof(OBJECT_DIRECTORY_INFORMATION));
        bool first = true;
        while (true) {
            st = NtQueryDirectoryObject(dirHandle, buf, bufSize, false, first, ref ctx, out retLen);
            first = false;
            if (st != 0 && st != 0x105) break; // STATUS_SUCCESS or STATUS_MORE_ENTRIES (0x105)
            int offset = 0;
            bool done = false;
            while (offset + entrySize <= retLen) {
                var odi = (OBJECT_DIRECTORY_INFORMATION)Marshal.PtrToStructure(buf + offset, typeof(OBJECT_DIRECTORY_INFORMATION));
                string nm = null, tp = null;
                if (odi.Name.Buffer != IntPtr.Zero) nm = Marshal.PtrToStringUni(odi.Name.Buffer);
                if (odi.TypeName.Buffer != IntPtr.Zero) tp = Marshal.PtrToStringUni(odi.TypeName.Buffer);
                if (string.IsNullOrEmpty(nm)) { done = true; break; }
                results.Add(nm + " : " + tp);
                offset += entrySize;
            }
            if (done || st != 0x105) break;
        }
        Marshal.FreeHGlobal(buf);
        NtClose(dirHandle);
        return results;
    }
}
'@

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log, $csSrc)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-PORT3 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
    try {
        Add-Type -TypeDefinition $csSrc -Language CSharp -ErrorAction Stop
        GW "Add-Type OK"
    } catch {
        GW "Add-Type FAILED: $($_.Exception.Message) / $($_.Exception.InnerException.Message)"
        return
    }

    GW "--- root object namespace: entries containing 'AnXin' ---"
    $all = [ObEnum]::Enumerate('\\')
    GW "    root total entries: $($all.Count)"
    $all | Where-Object { $_ -match 'AnXin|FileProtect' } | ForEach-Object { GW "    ROOT: $_" }

    GW "--- recursively search common dirs for AnXin/FileProtect objects ---"
    foreach ($d in @('\\Device','\\FileSystem','\\GLOBALROOT','\\BaseNamedObjects','\\Driver','\\Callback','\\Sessions')) {
        $e = [ObEnum]::Enumerate($d)
        if ($e.Count -eq 0) { GW "    $d : (empty or open-fail: $($e -join ','))" }
        else {
            $hits = $e | Where-Object { $_ -match 'AnXin|FileProtect|Filter' }
            if ($hits) { $hits | ForEach-Object { GW "    $d :: $_" } }
            else { GW "    $d : $($e.Count) entries, no AnXin/Filter hits" }
        }
    }

    "=== GUEST-PORT3 DONE ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-diag-port3-guest.log', $cs

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-port3-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port3-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== diag-port3 done ==="
