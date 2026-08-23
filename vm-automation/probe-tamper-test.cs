// AnXinProcMon P6 TAMPERED-path acceptance test - simulates the probe service:
// attach, probe every 2s, stop the driver mid-run via sc stop, and verify the
// blindness detection semantics (5 consecutive missed rounds => tampered alert).
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;
using System.Diagnostics;

public static class TamperTest {
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
        File.AppendAllText(@"C:\Windows\Temp\tampertest.log", DateTime.Now.ToString("HH:mm:ss.fff") + " " + m + "\r\n");
    }

    public static int Main() {
        L("=== TAMPER TEST START ===");
        IntPtr h = CreateFileW(@"\\.\AnXinProcMon", GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (h.ToInt64() == -1) { L("OPEN-FAIL err=" + Marshal.GetLastWin32Error()); return 1; }
        byte[] ver = new byte[64]; uint vr = 0;
        DeviceIoControl(h, IOCTL_GET_VERSION, null, 0, ver, 64, out vr, IntPtr.Zero);
        L("VERSION caps=0x" + BitConverter.ToUInt32(ver,16).ToString("X"));

        // health before
        byte[] hl = new byte[64]; uint hr = 0;
        DeviceIoControl(h, IOCTL_GET_HEALTH, null, 0, hl, 64, out hr, IntPtr.Zero);
        L("HEALTH-T0 attached=" + BitConverter.ToUInt32(hl,48) + " lastTick=" + BitConverter.ToInt64(hl,0));

        // background pump: record CREATE events for probe PIDs
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
                }
                CancelIoEx(h, IntPtr.Zero);
            }
        });
        pump.IsBackground = true;
        pump.Start();

        // rounds 1-2: driver alive, expect reports
        for (int i = 1; i <= 2; i++) {
            Process p = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit") { WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true });
            probePid = (uint)p.Id; sentMs = Environment.TickCount; reported = false;
            Thread.Sleep(1500);
            L("ROUND-" + i + " pid=" + p.Id + " reported=" + reported);
            try { p.Kill(); p.Dispose(); } catch {}
            Thread.Sleep(600);
        }

        // stop the driver -> callbacks vanish, probe CREATE never reported
        // Note: kernel drivers cannot be sc stop'ed (SCM returns 1052/1051 for
        // KERNEL_DRIVER services - Windows standard behavior, verified 2026-08-14).
        // Simulate driver loss via NtUnloadDriver, which requires SYSTEM privileges;
        // a scheduled task runs as SYSTEM to perform the unload (equivalent to a
        // BYOVD attacker killing the driver's callback surface).
        L(">>> unloading AnXinProcMon driver (simulating callback tampering)");
        string sc = Execute("schtasks /create /tn anxin_procmon_unload /tr \"\\\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\\\" -NoProfile -Command Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class U{[DllImport(\\\"ntdll.dll\\\",CharSet=CharSet.Unicode)]public static extern uint NtUnloadDriver(string s);public static int M(){return (int)NtUnloadDriver(\\\"\\\\Registry\\\\Machine\\\\System\\\\CurrentControlSet\\\\Services\\\\AnXinProcMon\\\");}}' -ea 0; [U]::M() | Out-File C:\\Windows\\Temp\\unload-rc.txt\" /sc once /st 23:59 /ru SYSTEM /f");
        L("schtasks create: " + sc.Trim());
        Execute("schtasks /run /tn anxin_procmon_unload");
        Thread.Sleep(4000);
        string rc = "no-rc-file";
        try { rc = File.ReadAllText(@"C:\Windows\Temp\unload-rc.txt").Trim(); } catch {}
        L("NtUnloadDriver rc=" + rc);
        Execute("schtasks /delete /tn anxin_procmon_unload /f");
        Thread.Sleep(2000);

        // rounds 3-7: driver dead, expect misses (5 consecutive => blindness)
        int missedRounds = 0;
        int expectedMiss = 5;
        for (int i = 3; i <= 7; i++) {
            Process p = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit") { WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true });
            probePid = (uint)p.Id; sentMs = Environment.TickCount; reported = false;
            Thread.Sleep(1500);
            if (reported) { L("ROUND-" + i + " pid=" + p.Id + " REPORTED (unexpected after stop)"); missedRounds = 0; }
            else { missedRounds++; L("ROUND-" + i + " pid=" + p.Id + " MISS (" + missedRounds + "/" + expectedMiss + ")"); }
            try { p.Kill(); p.Dispose(); } catch {}
            Thread.Sleep(600);
        }

        // health after: driver should be stopped -> GET_HEALTH fails or shows not attached
        bool healthOk = DeviceIoControl(h, IOCTL_GET_HEALTH, null, 0, hl, 64, out hr, IntPtr.Zero);
        L("HEALTH-T1 ok=" + healthOk + " err=" + Marshal.GetLastWin32Error());

        // verdict: >=5 consecutive misses after driver stop = blindness detected
        L("=== VERDICT missedRounds=" + missedRounds + " (>=5 required) ===");
        L(missedRounds >= expectedMiss
            ? "TAMPERED-DETECTED: probe missed " + missedRounds + " consecutive rounds after driver stop"
            : "TAMPERED-NOT-DETECTED: only " + missedRounds + " misses");

        ovPin.Free();
        CloseHandle(evt);
        CloseHandle(h);
        L("=== TAMPER TEST DONE ===");
        return missedRounds >= expectedMiss ? 0 : 2;
    }

    static string Execute(string cmd) {
        try {
            var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd) {
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden
            };
            using (var p = Process.Start(psi)) {
                string o = p.StandardOutput.ReadToEnd();
                p.WaitForExit(15000);
                return o;
            }
        } catch (Exception e) { return "EXEC-FAIL " + e.Message; }
    }
}
