$src = @'
using System;
using System.Runtime.InteropServices;
public class Dsp {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DEVMODE {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
        public short dmSpecVersion; public short dmDriverVersion; public short dmSize; public short dmDriverExtra;
        public int dmFields;
        public int dmPositionX; public int dmPositionY;
        public int dmDisplayOrientation; public int dmDisplayFixedOutput;
        public short dmColor; public short dmDuplex; public short dmYResolution; public short dmTTOption; public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
        public short dmLogPixels; public int dmBitsPerPel; public int dmPelsWidth; public int dmPelsHeight;
        public int dmDisplayFlags; public int dmDisplayFrequency; public int dmICMMethod; public int dmICMIntent;
        public int dmMediaType; public int dmDitherType; public int dmReserved1; public int dmReserved2;
        public int dmPanningWidth; public int dmPanningHeight;
    }
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int ChangeDisplaySettingsEx(string dev, ref DEVMODE dm, IntPtr hwnd, uint flags, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int ChangeDisplaySettingsEx(string dev, IntPtr dm, IntPtr hwnd, uint flags, IntPtr lParam);
}
'@
Add-Type -TypeDefinition $src
$dm = New-Object Dsp+DEVMODE
$dm.dmSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Dsp+DEVMODE])
$dm.dmFields = 0x80000 -bor 0x100000 -bor 0x20  # PELSWIDTH|PELSHEIGHT|POSITION
$dm.dmPelsWidth = 1920
$dm.dmPelsHeight = 1080
$dm.dmPositionX = 30000
$dm.dmPositionY = 30000
$r = [Dsp]::ChangeDisplaySettingsEx("\\.\DISPLAY2", [ref]$dm, [IntPtr]::Zero, 1, [IntPtr]::Zero)
Write-Output "DISPLAY2 attach 1920x1080: $r"
$r2 = [Dsp]::ChangeDisplaySettingsEx("\\.\DISPLAY2", [IntPtr]::Zero, [IntPtr]::Zero, 0, [IntPtr]::Zero)
Write-Output "DISPLAY2 query-null: $r2"
