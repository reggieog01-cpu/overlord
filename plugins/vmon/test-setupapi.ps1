$src = @'
using System;
using System.Runtime.InteropServices;
public class SetupApiTest {
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid classGuid, IntPtr hwndParent);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiCreateDeviceInfoW(IntPtr deviceInfoSet, string deviceName, ref Guid classGuid, string deviceDescription, IntPtr hwndParent, uint creationFlags, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiSetDeviceRegistryPropertyW(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, uint property, byte[] propertyBuffer, uint propertyBufferSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiCallClassInstaller(uint installFunction, IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool UpdateDriverForPlugAndPlayDevicesW(IntPtr hwndParent, string hardwareId, string fullInfPath, uint installFlags, out bool bRebootRequired);

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    public static string Test() {
        var sb = new System.Text.StringBuilder();
        Guid display = new Guid("4d36e968-e325-11ce-bfc1-08002be10318");
        IntPtr list = SetupDiCreateDeviceInfoList(ref display, IntPtr.Zero);
        sb.AppendLine("list: " + list + " err=" + Marshal.GetLastWin32Error());
        if (list == IntPtr.Zero || list == new IntPtr(-1)) return sb.ToString();

        var did = new SP_DEVINFO_DATA();
        did.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
        bool ok = SetupDiCreateDeviceInfoW(list, "Root\\MttVDD", ref display, "Virtual Display Driver", IntPtr.Zero, 1, ref did);
        sb.AppendLine("CreateDeviceInfoW Root\\MttVDD: " + ok + " err=0x" + Marshal.GetLastWin32Error().ToString("X"));
        if (!ok) return sb.ToString();

        string hwid = "Root\\MttVDD\0\0";
        byte[] hwidBytes = System.Text.Encoding.Unicode.GetBytes(hwid);
        ok = SetupDiSetDeviceRegistryPropertyW(list, ref did, 1, hwidBytes, (uint)hwidBytes.Length);
        sb.AppendLine("SetHwid: " + ok + " err=0x" + Marshal.GetLastWin32Error().ToString("X"));

        ok = SetupDiCallClassInstaller(25, list, ref did); // DIF_REGISTERDEVICE
        sb.AppendLine("RegisterDevice: " + ok + " err=0x" + Marshal.GetLastWin32Error().ToString("X"));

        bool reboot;
        ok = UpdateDriverForPlugAndPlayDevicesW(IntPtr.Zero, "Root\\MttVDD", @"C:\Users\vboxuser\AppData\Local\Temp\vmon-drv\MttVDD.inf", 1, out reboot);
        sb.AppendLine("BindDriver: " + ok + " err=0x" + Marshal.GetLastWin32Error().ToString("X") + " reboot=" + reboot);
        return sb.ToString();
    }
}
'@
Add-Type -TypeDefinition $src -Language CSharp
[SetupApiTest]::Test() | Out-File 'C:\Users\vboxuser\AppData\Local\Temp\vmon-setupapi.log' -Encoding utf8
