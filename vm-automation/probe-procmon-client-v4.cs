// AnXinProcMon P6 probe acceptance test v4 - async pump records all CREATE events;
// the main thread launches probe processes; results are matched by PID.
// This tolerates the busy guest's interleaved IMAGE_LOAD events.
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;

public static class ProbeTestV4 {
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
    const uint EVT_PROC_CREATE = 1;

    static readonly List<uint> probePids = new List<uint>();
    static readonly List<long> probeSentTicks = new List<long>();
    static readonly object matchLock = new object();
    static long pumpStartTick = 0;

    static void L(string m) {
        File.AppendAllText(@"C:\Windows\Temp\probev4.log", DateTime.Now.ToString("HH:mm:ss.fff") + " " + m + "\r\n");
    }

    public static int Main() {
        L("start");
        IntPtr h = CreateFileW(@"\\.\AnXinProcMon", GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        L("open err=" + Marshal.GetLastWin32Error());
        if (h.ToInt64() == -1) return 1;

        byte[] ver = new byte[64]; uint ret = 0;
        bool ok = DeviceIoControl(h, IOCTL_GET_VERSION, null, 0, ver, 64, out ret, IntPtr.Zero);
        L("VERSION ok=" + ok + " proto=" + BitConverter.ToUInt32(ver,0) + " caps=0x" + BitConverter.ToUInt32(ver,16).ToString("X"));
        if (!ok) return 1;

        byte[] hl = new byte[64]; uint hr = 0;
        DeviceIoControl(h, IOCTL_GET_HEALTH, null, 0, hl, 64, out hr, IntPtr.Zero);
        L("HEALTH-T0 lcQ=" + BitConverter.ToUInt64(hl,8) + " lcDepth=" + BitConverter.ToUInt32(hl,40) + " attached=" + BitConverter.ToUInt32(hl,48));

        pumpStartTick = Environment.TickCount;

        // background pump: pend async, record every CREATE event
        Thread pump = new Thread(() => {
            IntPtr evt = CreateEventW(IntPtr.Zero, true, false, null);
            byte[] buf = new byte[48 + 4096];
            OVERLAPPED ov = new OVERLAPPED(); ov.hEvent = evt;
            GCHandle ovPin = GCHandle.Alloc(ov, GCHandleType.Pinned);
            IntPtr ovPtr = ovPin.AddrOfPinnedObject();
            int seen = 0;
            while (Environment.TickCount - pumpStartTick < 15000) {
                uint pr = 0;
                bool pendOk = DeviceIoControl(h, IOCTL_GET_LIFECYCLE_EVENTS, null, 0, buf, (uint)buf.Length, out pr, ovPtr);
                if (!pendOk) { L("pump pend-fail err=" + Marshal.GetLastWin32Error()); break; }
                uint w = WaitForSingleObject(evt, 2000);
                if (w == 0) {
                    uint gr = 0;
                    bool got = GetOverlappedResult(h, ovPtr, out gr, false);
                    if (got && gr >= 48) {
                        uint pid = BitConverter.ToUInt32(buf, 16);
                        uint etype = BitConverter.ToUInt16(buf, 40);
                        seen++;
                        if (etype == EVT_PROC_CREATE) {
                            L("CREATE pid=" + pid + " at+" + (Environment.TickCount - pumpStartTick) + "ms");
                        }
                    }
                }
                CancelIoEx(h, IntPtr.Zero);
            }
            L("pump done, events seen=" + seen);
            ovPin.Free();
            CloseHandle(evt);
        });
        pump.IsBackground = true;
        pump.Start();

        // main thread: launch probe processes, record PIDs + send time
        for (int i = 1; i <= 4; i++) {
            try {
                Process p = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit") { WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true });
                lock (matchLock) {
                    probePids.Add((uint)p.Id);
                    probeSentTicks.Add(Environment.TickCount);
                }
                L("PROBE-" + i + " sent pid=" + p.Id + " at+" + (Environment.TickCount - pumpStartTick) + "ms");
                try { p.WaitForExit(2000); } catch {}
                try { p.Kill(); p.Dispose(); } catch {}
            } catch (Exception e) {
                L("PROBE-" + i + " start-fail " + e.Message);
            }
            Thread.Sleep(1200);
        }

        // wait for pump to finish collecting
        pump.Join(16000);

        // match
        L("=== PROBE MATCH RESULTS ===");
        int matched = 0;
        for (int i = 0; i < probePids.Count; i++) {
            // parse the log for "CREATE pid=<pid>"
            string log = File.ReadAllText(@"C:\Windows\Temp\probev4.log");
            string needle = "CREATE pid=" + probePids[i];
            if (log.Contains(needle)) {
                matched++;
                L("  MATCH pid=" + probePids[i] + " (sent at+" + (probeSentTicks[i] - pumpStartTick) + "ms)");
            } else {
                L("  MISS  pid=" + probePids[i]);
            }
        }
        L("MATCHED " + matched + "/" + probePids.Count);

        CancelIoEx(h, IntPtr.Zero);
        Thread.Sleep(200);
        bool ch = CloseHandle(h);
        L("close ok=" + ch + " err=" + Marshal.GetLastWin32Error());
        L("done");
        return matched == probePids.Count ? 0 : 2;
    }
}
