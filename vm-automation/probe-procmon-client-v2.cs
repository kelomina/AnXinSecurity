// AnXinProcMon P6 probe acceptance test v2 - OVERLAPPED async IOCTL to avoid
// blocking-IO cancel hangs; logs every step to a file. Run inside the guest.
// Compiled with: csc /unsafe probe-procmon-client-v2.cs
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;
using System.Diagnostics;

public static class ProbeTestV2 {
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
        File.AppendAllText(@"C:\Windows\Temp\probev2.log", DateTime.Now.ToString("HH:mm:ss.fff") + " " + m + "\r\n");
    }

    public static int Main() {
        L("start");
        IntPtr h = CreateFileW(@"\\.\AnXinProcMon", GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        L("open err=" + Marshal.GetLastWin32Error());
        if (h.ToInt64() == -1) return 1;

        // version handshake (attach)
        byte[] ver = new byte[64]; uint ret = 0;
        bool ok = DeviceIoControl(h, IOCTL_GET_VERSION, null, 0, ver, 64, out ret, IntPtr.Zero);
        L("VERSION ok=" + ok + " proto=" + BitConverter.ToUInt32(ver,0) + " caps=0x" + BitConverter.ToUInt32(ver,16).ToString("X"));
        if (!ok) return 1;

        // health before probe
        byte[] hl = new byte[64]; uint hr = 0;
        DeviceIoControl(h, IOCTL_GET_HEALTH, null, 0, hl, 64, out hr, IntPtr.Zero);
        L("HEALTH-T0 lcQ=" + BitConverter.ToUInt64(hl,8) + " lcDepth=" + BitConverter.ToUInt32(hl,40));

        // async pump: pend GET_LIFECYCLE_EVENTS with OVERLAPPED, probe while pended
        IntPtr evt = CreateEventW(IntPtr.Zero, true, false, null);
        byte[] buf = new byte[48 + 4096];
        OVERLAPPED ov = new OVERLAPPED(); ov.hEvent = evt;
        uint pr = 0;
        bool pendOk;
        unsafe {
            pendOk = DeviceIoControl(h, IOCTL_GET_LIFECYCLE_EVENTS, null, 0, buf, (uint)buf.Length, out pr, (IntPtr)(&ov));
        }
        int pendErr = Marshal.GetLastWin32Error();
        L("pump pend ok=" + pendOk + " err=" + pendErr + " ret=" + pr);

        // create probe processes while the pump is pended
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

        // wait for the pended pump to complete (up to 5s)
        uint wait = WaitForSingleObject(evt, 5000);
        L("pump wait=" + wait + " (0=signaled, 0x102=timeout)");
        if (wait == 0) {
            bool got;
            unsafe {
                got = GetOverlappedResult(h, (IntPtr)(&ov), out pr, false);
            }
            L("pump result got=" + got + " err=" + Marshal.GetLastWin32Error() + " ret=" + pr);
            if (got && pr >= 48) {
                L("EVENT pid=" + BitConverter.ToUInt32(buf,16) + " evt=" + BitConverter.ToUInt16(buf,40) +
                  " parent=" + BitConverter.ToUInt32(buf,20) + " creator=" + BitConverter.ToUInt32(buf,24) +
                  " seq=" + BitConverter.ToUInt32(buf,36));
            }
        }

        // cancel any pending IO, then health again
        CancelIoEx(h, IntPtr.Zero);
        Thread.Sleep(200);
        DeviceIoControl(h, IOCTL_GET_HEALTH, null, 0, hl, 64, out hr, IntPtr.Zero);
        L("HEALTH-T1 lcQ=" + BitConverter.ToUInt64(hl,8) + " lcDepth=" + BitConverter.ToUInt32(hl,40) + " attached=" + BitConverter.ToUInt32(hl,48));

        // cleanup
        bool ch = CloseHandle(h);
        L("close ok=" + ch + " err=" + Marshal.GetLastWin32Error());
        CloseHandle(evt);
        L("done");
        return 0;
    }
}
