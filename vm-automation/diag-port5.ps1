# diag-port5.ps1 - 用可靠的 NtQueryDirectoryObject 枚举实现定位 AnXinFileProtectPort。Host-side.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port5.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-port5 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

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
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class ObDump {
    [DllImport("ntdll.dll", CharSet=CharSet.Unicode)]
    static extern int NtOpenDirectoryObject(out IntPtr Handle, uint DesiredAccess,
        ref OBJECT_ATTRIBUTES Oa);
    [DllImport("ntdll.dll")]
    static extern int NtQueryDirectoryObject(IntPtr DirectoryHandle, IntPtr Buffer,
        int BufferLength, bool ReturnSingleEntry, bool RestartScan, ref uint Context,
        out uint ReturnLength);
    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr Handle);

    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES {
        public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
        public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_DIRECTORY_INFORMATION { public UNICODE_STRING Name; public UNICODE_STRING TypeName; }

    static UNICODE_STRING MakeStr(string s) {
        var u = new UNICODE_STRING();
        u.Buffer = Marshal.StringToHGlobalUni(s);
        u.Length = (ushort)(s.Length * 2);
        u.MaximumLength = (ushort)(s.Length * 2 + 2);
        return u;
    }

    public static List<string> List(string dir) {
        var res = new List<string>();
        IntPtr h = IntPtr.Zero;
        var name = MakeStr(dir);
        var oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        var namePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(name, namePtr, false);
        oa.ObjectName = namePtr;
        oa.Attributes = 0x40;
        int st = NtOpenDirectoryObject(out h, 0x0001, ref oa);
        Marshal.FreeHGlobal(namePtr);
        if (st != 0) { res.Add("OPEN_FAIL 0x" + st.ToString("X8")); return res; }

        IntPtr buf = Marshal.AllocHGlobal(1 << 20);
        uint ctx = 0, retLen = 0;
        int entrySize = Marshal.SizeOf(typeof(OBJECT_DIRECTORY_INFORMATION));
        for (int pass = 0; pass < 20; pass++) {
            st = NtQueryDirectoryObject(h, buf, 1 << 20, false, pass == 0, ref ctx, out retLen);
            if (st != 0 && st != 0x105) { res.Add("QUERY_END 0x" + st.ToString("X8") + " pass=" + pass); break; }
            int off = 0;
            bool stop = false;
            while (off + entrySize <= (int)retLen) {
                var odi = (OBJECT_DIRECTORY_INFORMATION)Marshal.PtrToStructure(buf + off, typeof(OBJECT_DIRECTORY_INFORMATION));
                string nm = odi.Name.Buffer == IntPtr.Zero ? null : Marshal.PtrToStringUni(odi.Name.Buffer);
                if (string.IsNullOrEmpty(nm)) { stop = true; break; }
                string tp = odi.TypeName.Buffer == IntPtr.Zero ? null : Marshal.PtrToStringUni(odi.TypeName.Buffer);
                res.Add(nm + "\t" + tp);
                off += entrySize;
            }
            if (stop || st != 0x105) break;
        }
        Marshal.FreeHGlobal(buf);
        NtClose(h);
        return res;
    }
}
'@

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log, $csSrc)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-PORT5 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
    try {
        Add-Type -TypeDefinition $csSrc -Language CSharp -ErrorAction Stop
        GW "Add-Type OK"
    } catch {
        GW "Add-Type FAILED: $($_.Exception.Message) / $($_.Exception.InnerException.Message)"
        return
    }
    foreach ($d in @('\\','\\Device','\\FileSystem','\\Callback','\\Driver','\\GLOBALROOT')) {
        $r = [ObDump]::List($d)
        GW "=== $d : $($r.Count) entries ==="
        $r | ForEach-Object { GW "    $_" }
        $hits = $r | Where-Object { $_ -match 'AnXin|FileProtect|FltMgr|Filter' }
        $hits | ForEach-Object { GW "    HIT: $d :: $_" }
    }
    "=== GUEST-PORT5 DONE ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-diag-port5-guest.log', $cs

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-port5-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port5-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== diag-port5 done ==="
