// AnXinProcMon P6 acceptance probe test - compiled in the guest via Add-Type.
// Verifies: GET_VERSION, GET_HEALTH, lifecycle event pump, 100ms probe report (contract 13.7).
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public static class ProbeTest {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inb, uint inl, byte[] outb, uint outl, out uint ret, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, IntPtr si, out PROCESS_INFORMATION pi);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }

    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint OPEN_EXISTING = 3, FILE_ATTRIBUTE_NORMAL = 0x80;
    const uint IOCTL_GET_VERSION = 0x00226800;
    const uint IOCTL_GET_LIFECYCLE_EVENTS = 0x00226804;
    const uint IOCTL_GET_HEALTH = 0x00226810;
    const uint EVT_PROC_CREATE = 1;

    static uint probePid = 0;
    static long probeSentMs = 0;
    static long reportLatencyMs = -1;
    static int reportCount = 0;
    static int versionOk = 0;
    static readonly object probeLock = new object();

    public static string Run() {
        var sb = new System.Text.StringBuilder();
        IntPtr h = CreateFileW(@"\\.\AnXinProcMon", GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (h.ToInt64() == -1) return "DEVICE-OPEN-FAIL err=" + Marshal.GetLastWin32Error();
        sb.AppendLine("device open OK");

        // 1. GET_VERSION
        byte[] ver = new byte[256]; uint ret = 0;
        bool ok = DeviceIoControl(h, IOCTL_GET_VERSION, null, 0, ver, 256, out ret, IntPtr.Zero);
        if (!ok || ret < 28) return "VERSION-FAIL ok=" + ok + " ret=" + ret + " err=" + Marshal.GetLastWin32Error();
        uint proto = BitConverter.ToUInt32(ver, 0);
        uint major = BitConverter.ToUInt32(ver, 4);
        uint minor = BitConverter.ToUInt32(ver, 8);
        uint patch = BitConverter.ToUInt32(ver, 12);
        uint caps  = BitConverter.ToUInt32(ver, 16);
        sb.AppendLine("VERSION proto=" + proto + " driver=" + major + "." + minor + "." + patch + " caps=0x" + caps.ToString("X"));
        versionOk = (proto == 1 && (caps & 0x01) != 0) ? 1 : 0;

        // 2. GET_HEALTH
        byte[] hl = new byte[64]; uint hret = 0;
        ok = DeviceIoControl(h, IOCTL_GET_HEALTH, null, 0, hl, 64, out hret, IntPtr.Zero);
        if (!ok || hret < 56) sb.AppendLine("HEALTH-FAIL ok=" + ok + " ret=" + hret + " err=" + Marshal.GetLastWin32Error());
        else {
            long lastTick = BitConverter.ToInt64(hl, 0);
            ulong lcQueued = BitConverter.ToUInt64(hl, 8);
            ulong lcDropped = BitConverter.ToUInt64(hl, 16);
            ulong bhQueued = BitConverter.ToUInt64(hl, 24);
            ulong bhDropped = BitConverter.ToUInt64(hl, 32);
            uint lcDepth = BitConverter.ToUInt32(hl, 40);
            uint bhDepth = BitConverter.ToUInt32(hl, 44);
            uint attached = BitConverter.ToUInt32(hl, 48);
            sb.AppendLine("HEALTH lastTick=" + lastTick + " lcQueued=" + lcQueued + " lcDropped=" + lcDropped +
                          " bhQueued=" + bhQueued + " bhDropped=" + bhDropped + " lcDepth=" + lcDepth + " bhDepth=" + bhDepth + " attached=" + attached);
        }

        // 3. Drain backlogged lifecycle events first (from earlier attach sessions),
        //    then start the pump that only reports probe PIDs.
        int drained = 0;
        var drainDeadline = Environment.TickCount + 3000;
        while (Environment.TickCount < drainDeadline) {
            uint rr = 0;
            byte[] dbuf = new byte[48 + 4096];
            bool dok = DeviceIoControl(h, IOCTL_GET_LIFECYCLE_EVENTS, null, 0, dbuf, (uint)dbuf.Length, out rr, IntPtr.Zero);
            if (!dok) break;
            if (rr < 48) continue;
            drained++;
        }
        sb.AppendLine("drained backlog: " + drained + " events");

        // event pump thread: block on GET_LIFECYCLE_EVENTS, match probe PID
        Thread pump = new Thread(() => {
            byte[] buf = new byte[48 + 4096];
            while (true) {
                uint r = 0;
                bool eok = DeviceIoControl(h, IOCTL_GET_LIFECYCLE_EVENTS, null, 0, buf, (uint)buf.Length, out r, IntPtr.Zero);
                if (!eok) return;
                if (r < 48) continue;
                uint pid = BitConverter.ToUInt32(buf, 16);
                uint evt = BitConverter.ToUInt16(buf, 40);
                uint target;
                long sent;
                lock (probeLock) { target = probePid; sent = probeSentMs; }
                if (target != 0 && pid == target && evt == EVT_PROC_CREATE) {
                    lock (probeLock) {
                        reportLatencyMs = Environment.TickCount - sent;
                        reportCount++;
                        probePid = 0;
                    }
                }
            }
        });
        pump.IsBackground = true;
        pump.Start();

        // 4. active probe: 6 rounds, one probe every 2s, expect report within 100ms
        for (int i = 1; i <= 6; i++) {
            PROCESS_INFORMATION pi;
            bool cp = CreateProcessW(null, "cmd.exe /c exit", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, IntPtr.Zero, out pi);
            if (!cp) { sb.AppendLine("PROBE-" + i + " CreateProcess FAIL err=" + Marshal.GetLastWin32Error()); break; }
            lock (probeLock) {
                probePid = pi.dwProcessId;
                probeSentMs = Environment.TickCount;
            }
            Thread.Sleep(100);
            int reps; long lat;
            lock (probeLock) { reps = reportCount; lat = reportLatencyMs; }
            sb.AppendLine("PROBE-" + i + " pid=" + pi.dwProcessId + " reported=" + reps + " latencyMs=" + lat);
            Thread.Sleep(1900);
        }

        // 5. final health
        Thread.Sleep(500);
        ok = DeviceIoControl(h, IOCTL_GET_HEALTH, null, 0, hl, 64, out hret, IntPtr.Zero);
        if (ok && hret >= 56) {
            long lastTick2 = BitConverter.ToInt64(hl, 0);
            ulong lcQueued2 = BitConverter.ToUInt64(hl, 8);
            sb.AppendLine("HEALTH-FINAL lastTick=" + lastTick2 + " lcQueued=" + lcQueued2);
        }

        CloseHandle(h);
        int finalCount; long finalLat;
        lock (probeLock) { finalCount = reportCount; finalLat = reportLatencyMs; }
        sb.Append("RESULT versionOk=" + versionOk + " reports=" + finalCount + " lastLatencyMs=" + finalLat);
        return sb.ToString();
    }
}

// Console entry point when compiled as an exe (Add-Type in the guest uses the class directly).
public static class ProbeMain {
    public static int Main(string[] args) {
        System.Console.WriteLine(ProbeTest.Run());
        return 0;
    }
}
