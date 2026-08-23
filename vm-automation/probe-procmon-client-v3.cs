// AnXinProcMon P6 probe acceptance test v3 - no unsafe; GCHandle-pinned OVERLAPPED.
// Verifies GET_VERSION, GET_HEALTH, async lifecycle pump and 100ms probe report.
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;
using System.Diagnostics;

public static class ProbeTestV3 {
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

    static void L(string m) {
        File.AppendAllText(@"C:\Windows\Temp\probev3.log", DateTime.Now.ToString("HH:mm:ss.fff") + " " + m + "\r\n");
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

        // drain backlog completely: pend + wait until timeout (queue empty)
        int drained = 0;
        bool drainedDone = false;
        for (int d = 0; d < 600; d++) {
            IntPtr devt = CreateEventW(IntPtr.Zero, true, false, null);
            byte[] dbuf = new byte[48 + 4096];
            OVERLAPPED dov = new OVERLAPPED(); dov.hEvent = devt;
            GCHandle dpin = GCHandle.Alloc(dov, GCHandleType.Pinned);
            IntPtr dptr = dpin.AddrOfPinnedObject();
            uint dr = 0;
            bool dok = DeviceIoControl(h, IOCTL_GET_LIFECYCLE_EVENTS, null, 0, dbuf, (uint)dbuf.Length, out dr, dptr);
            if (!dok) { dpin.Free(); CloseHandle(devt); break; }
            uint dw = WaitForSingleObject(devt, 1000);
            if (dw != 0) {
                // timeout = queue empty (no event within 1s)
                CancelIoEx(h, IntPtr.Zero);
                dpin.Free(); CloseHandle(devt);
                drainedDone = true;
                break;
            }
            GetOverlappedResult(h, dptr, out dr, false);
            drained++;
            dpin.Free(); CloseHandle(devt);
        }
        L("drained backlog: " + drained + " (empty=" + drainedDone + ")");

        // async pump: pend GET_LIFECYCLE_EVENTS with OVERLAPPED, probe while pended.
        // Records EVERY CREATE event (pid + arrival time) so probe PIDs can be
        // matched even when the busy guest interleaves many IMAGE_LOAD events.
        IntPtr evt = CreateEventW(IntPtr.Zero, true, false, null);
        byte[] buf = new byte[48 + 4096];
        OVERLAPPED ov = new OVERLAPPED(); ov.hEvent = evt;
        GCHandle ovPin = GCHandle.Alloc(ov, GCHandleType.Pinned);
        IntPtr ovPtr = ovPin.AddrOfPinnedObject();
        uint pr = 0;
        bool pendOk = DeviceIoControl(h, IOCTL_GET_LIFECYCLE_EVENTS, null, 0, buf, (uint)buf.Length, out pr, ovPtr);
        int pendErr = Marshal.GetLastWin32Error();
        L("pump pend ok=" + pendOk + " err=" + pendErr + " ret=" + pr);

        System.Collections.Generic.List<uint> createdPids = new System.Collections.Generic.List<uint>();
        System.Collections.Generic.List<long> createdAt = new System.Collections.Generic.List<long>();

        // pump loop: pend async, wait up to 1s, record CREATE events
        long pumpStart = Environment.TickCount;
        int pumpEvents = 0;
        while (Environment.TickCount - pumpStart < 12000) {
            if (!pendOk) break;
            uint w = WaitForSingleObject(evt, 1000);
            if (w == 0) {
                uint gr = 0;
                bool got = GetOverlappedResult(h, ovPtr, out gr, false);
                if (got && gr >= 48) {
                    uint pid = BitConverter.ToUInt32(buf, 16);
                    uint etype = BitConverter.ToUInt16(buf, 40);
                    pumpEvents++;
                    if (etype == EVT_PROC_CREATE) {
                        createdPids.Add(pid);
                        createdAt.Add(Environment.TickCount);
                        L("CREATE pid=" + pid + " at+" + (Environment.TickCount - pumpStart));
                    }
                }
            }
            // re-pend for the next event
            CancelIoEx(h, IntPtr.Zero);
            pr = 0;
            pendOk = DeviceIoControl(h, IOCTL_GET_LIFECYCLE_EVENTS, null, 0, buf, (uint)buf.Length, out pr, ovPtr);
        }
        L("pump events seen: " + pumpEvents + " creates: " + createdPids.Count);

        // match probe PIDs against observed CREATE events (probe loop ran in parallel)
        L("PROBE match results:");
        foreach (uint probePid in probePidList) {
            int idx = createdPids.IndexOf(probePid);
            if (idx >= 0) {
                L("  MATCH pid=" + probePid + " arrived at+" + (createdAt[idx] - pumpStart));
            } else {
                L("  MISS  pid=" + probePid);
            }
        }

        for (int i = 1; i <= 4; i++) {
            try {
                Process p = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit") { WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true });
                L("PROBE-" + i + " created pid=" + p.Id);
                try { p.WaitForExit(2000); } catch {}
                try { p.Kill(); p.Dispose(); } catch {}
            } catch (Exception e) {
                L("PROBE-" + i + " start-fail " + e.Message);
            }
            Thread.Sleep(500);
        }

        uint wait = WaitForSingleObject(evt, 5000);
        L("pump wait=" + wait + " (0=signaled, 0x102=timeout)");
        if (wait == 0) {
            bool got = GetOverlappedResult(h, ovPtr, out pr, false);
            L("pump result got=" + got + " err=" + Marshal.GetLastWin32Error() + " ret=" + pr);
            if (got && pr >= 48) {
                L("EVENT pid=" + BitConverter.ToUInt32(buf,16) + " evt=" + BitConverter.ToUInt16(buf,40) +
                  " parent=" + BitConverter.ToUInt32(buf,20) + " creator=" + BitConverter.ToUInt32(buf,24) +
                  " seq=" + BitConverter.ToUInt32(buf,36));
            }
        }

        CancelIoEx(h, IntPtr.Zero);
        Thread.Sleep(200);
        DeviceIoControl(h, IOCTL_GET_HEALTH, null, 0, hl, 64, out hr, IntPtr.Zero);
        L("HEALTH-T1 lcQ=" + BitConverter.ToUInt64(hl,8) + " lcDepth=" + BitConverter.ToUInt32(hl,40) + " attached=" + BitConverter.ToUInt32(hl,48));

        bool ch = CloseHandle(h);
        L("close ok=" + ch + " err=" + Marshal.GetLastWin32Error());
        ovPin.Free();
        CloseHandle(evt);
        L("done");
        return 0;
    }
}
