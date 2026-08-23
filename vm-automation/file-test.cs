using System;
using System.Runtime.InteropServices;
public static class FT3 {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] i, uint il, byte[] o, uint ol, out uint r, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    public static string R() {
        IntPtr h = CreateFileW(@"\\.\AnXinProcMon", 0xC0000000, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        if (h.ToInt64() == -1) return "OPEN-FAIL " + Marshal.GetLastWin32Error();
        byte[] v = new byte[64]; uint r = 0;
        DeviceIoControl(h, 0x00226800, null, 0, v, 64, out r, IntPtr.Zero);
        byte[] hl = new byte[64]; uint hr = 0;
        DeviceIoControl(h, 0x00226810, null, 0, hl, 64, out hr, IntPtr.Zero);
        ulong q0 = BitConverter.ToUInt64(hl, 24);
        System.Threading.Thread.Sleep(300);
        for (int i = 1; i <= 5; i++) {
            try { System.IO.File.WriteAllText(@"C:\Users\test\ft3_" + i + ".txt", "x"); } catch {}
            System.Threading.Thread.Sleep(200);
        }
        System.Threading.Thread.Sleep(1500);
        DeviceIoControl(h, 0x00226810, null, 0, hl, 64, out hr, IntPtr.Zero);
        ulong q1 = BitConverter.ToUInt64(hl, 24);
        CloseHandle(h);
        return "bhQ: " + q0 + " -> " + q1 + " (delta=" + (q1 - q0) + ")";
    }
}
