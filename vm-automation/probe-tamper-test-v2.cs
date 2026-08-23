// AnXinProcMon TAMPERED-path acceptance test v2 - simulates callback tampering by
// pushing a SET_FILTER DROP rule for cmd.exe (the probe process). The driver stays
// online but probe CREATE events are filtered out, equivalent to an attacker
// disabling the callback surface. Verifies the blindness detection (5 consecutive
// missed rounds => tampered alert semantics).
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;
using System.Diagnostics;

public static class TamperTest2 {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inb, uint inl, byte[] outb, uint outl, out uint ret, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateEventW(IntPtr sa, bool manual, bool init, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetOverlappedResult(IntPtr h, IntPtr ov, out uint ret, bool wait);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CancelIoEx(IntPtr h, IntPtr ov);

    [StructLayout(LayoutKind.Sequential)]
    public struct OVERLAPPED {
        public IntPtr Internal; public IntPtr InternalHigh;
        public uint Offset; public uint OffsetHigh; public IntPtr hEvent;
    }

    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint OPEN_EXISTING = 3, FILE_ATTRIBUTE_NORMAL = 0x80;
    const uint IOCTL_GET_VERSION = 0x00226800;
    const uint IOCTL_GET_LIFECYCLE_EVENTS = 0x00226804;
    const uint IOCTL_GET_HEALTH = 0x00226810;
    const uint IOCTL_SET_FILTER = 0x0022A80C;
    const uint EVT_PROC_CREATE = 1;
    const uint RULE_PROC_PATH_PREFIX = 3;
    const uint FILTER_DROP = 2;

    static void L(string m) {
        File.AppendAllText(@"C:\Windows\Temp\tampertest2.log", DateTime.Now.ToString("HH:mm:ss.fff") + " " + m + "\r\n");
    }

    // build SET_FILTER buffer: UINT32 Version + UINT32 Count + rules (UINT32 x4 + UTF-16 name)
    static byte[] BuildDropCmdFilter() {
        var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);
        bw.Write(1u); // version
        bw.Write(1u); // count
        bw.Write(RULE_PROC_PATH_PREFIX);
        bw.Write(FILTER_DROP);
        bw.Write(0u); // flags
        string name = "cmd.exe";
        bw.Write((uint)name.Length);
        foreach (char c in name) bw.Write((ushort)c);
        return ms.ToArray();
    }

    public static int Main() {
        L("=== TAMPER TEST V2 START ===");
        IntPtr h = CreateFileW(@"\\.\AnXinProcMon", GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (h.ToInt64() == -1) { L("OPEN-FAIL err=" + Marshal.GetLastWin32Error()); return 1; }
        byte[] ver = new byte[64]; uint vr = 0;
        DeviceIoControl(h, IOCTL_GET_VERSION, null, 0, ver, 64, out vr, IntPtr.Zero);
        L("VERSION caps=0x" + BitConverter.ToUInt32(ver,16).ToString("X"));

        byte[] hl = new byte[64]; uint hr = 0;
        DeviceIoControl(h, IOCTL_GET_HEALTH, null, 0, hl, 64, out hr, IntPtr.Zero);
        L("HEALTH-T0 attached=" + BitConverter.ToUInt32(hl,48) + " lastTick=" + BitConverter.ToInt64(hl,0));

        // pump: record CREATE events for probe PIDs
        IntPtr evt = CreateEventW(IntPtr.Zero, true, false, null);
        byte[] buf = new byte[48 + 4096];
        OVERLAPPED ov = new OVERLAPPED(); ov.hEvent = evt;
        GCHandle ovPin = GCHandle.Alloc(ov, GCHandleType.Pinned);
        IntPtr ovPtr = ovPin.AddrOfPinnedObject();
        uint probePid = 0; long sentMs = 0;
        bool reported = false;
        Thread pump = new Thread(() => {
            while (true) {
                uint pr = 0;
                bool ok = DeviceIoControl(h, IOCTL_GET_LIFECYCLE_EVENTS, null, 0, buf, (uint)buf.Length, out pr, ovPtr);
                if (!ok) { L("pump exit err=" + Marshal.GetLastWin32Error()); return; }
                uint w = WaitForSingleObject(evt, 3000);
                if (w == 0) {
                    uint gr = 0;
                    GetOverlappedResult(h, ovPtr, out gr, false);
                    if (gr >= 48) {
                        uint pid = BitConverter.ToUInt32(buf, 16);
                        uint etype = BitConverter.ToUInt16(buf, 40);
                        if (etype == EVT_PROC_CREATE && pid == probePid) {
                            L("PROBE-REPORT pid=" + pid + " latencyMs=" + (Environment.TickCount - sentMs));
                            reported = true;
                            probePid = 0;
                        }
                    }
                    // 事件已收到：直接 re-pend（不 cancel，避免 cancel-repend 间隙丢事件）
                    //  Event received: re-pend directly (no cancel; cancelling between
                    //  re-pends drops events that arrive in the gap)
                    continue;
                }
                // 超时（无事件）：取消挂起 IRP 后 re-pend
                //  Timeout: cancel the pended IRP, then re-pend
                CancelIoEx(h, IntPtr.Zero);
            }
        });
        pump.IsBackground = true;
        pump.Start();

        // rounds 1-2: no filter, expect reports
        for (int i = 1; i <= 2; i++) {
            Process p = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit") { WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true });
            probePid = (uint)p.Id; sentMs = Environment.TickCount; reported = false;
            Thread.Sleep(1500);
            L("ROUND-" + i + " pid=" + p.Id + " reported=" + reported);
            try { p.Kill(); p.Dispose(); } catch {}
            Thread.Sleep(600);
        }

        // push DROP filter for cmd.exe (driver online but probe events filtered)
        byte[] filter = BuildDropCmdFilter();
        bool setOk = DeviceIoControl(h, IOCTL_SET_FILTER, filter, (uint)filter.Length, null, 0, out hr, IntPtr.Zero);
        L("SET_FILTER drop cmd.exe ok=" + setOk + " err=" + Marshal.GetLastWin32Error());
        Thread.Sleep(1000);

        // rounds 3-7: probe CREATE filtered -> misses
        int missedRounds = 0;
        int expectedMiss = 5;
        for (int i = 3; i <= 7; i++) {
            Process p = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit") { WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true });
            probePid = (uint)p.Id; sentMs = Environment.TickCount; reported = false;
            Thread.Sleep(1500);
            if (reported) { L("ROUND-" + i + " pid=" + p.Id + " REPORTED (unexpected after filter)"); missedRounds = 0; }
            else { missedRounds++; L("ROUND-" + i + " pid=" + p.Id + " MISS (" + missedRounds + "/" + expectedMiss + ")"); }
            try { p.Kill(); p.Dispose(); } catch {}
            Thread.Sleep(600);
        }

        // restore: empty filter table (whole-table replace with 0 rules)
        byte[] empty = new byte[8]; // version + count=0
        BinaryWriter bw = new BinaryWriter(new MemoryStream());
        bw.Write(2u); bw.Write(0u);
        empty = ((MemoryStream)bw.BaseStream).ToArray();
        DeviceIoControl(h, IOCTL_SET_FILTER, empty, (uint)empty.Length, null, 0, out hr, IntPtr.Zero);
        L("SET_FILTER restored (empty table)");

        L("=== VERDICT missedRounds=" + missedRounds + " (>=5 required) ===");
        L(missedRounds >= expectedMiss
            ? "TAMPERED-DETECTED: probe missed " + missedRounds + " consecutive rounds under DROP filter"
            : "TAMPERED-NOT-DETECTED: only " + missedRounds + " misses");

        ovPin.Free();
        CloseHandle(evt);
        CloseHandle(h);
        L("=== TAMPER TEST V2 DONE ===");
        return missedRounds >= expectedMiss ? 0 : 2;
    }
}
