$src = @'
using System;
using System.Runtime.InteropServices;
public class Ccd {
    [DllImport("user32.dll")]
    public static extern int SetDisplayConfig(uint numPathArrayElements, IntPtr pathArray, uint numModeInfoArrayElements, IntPtr modeInfoArray, uint flags);
    [DllImport("user32.dll")]
    public static extern int GetDisplayConfigBufferSizes(uint flags, out uint numPaths, out uint numModes);
}
'@
Add-Type -TypeDefinition $src
# SDC_TOPOLOGY_EXTEND = 0x2, SDC_APPLY = 0x80
$r = [Ccd]::SetDisplayConfig(0, [IntPtr]::Zero, 0, [IntPtr]::Zero, 0x80 -bor 0x2)
Write-Output "SetDisplayConfig EXTEND: $r"
Add-Type -AssemblyName System.Windows.Forms
Start-Sleep -Seconds 2
[System.Windows.Forms.Screen]::AllScreens | ForEach-Object {
    Write-Output ("{0} | primary={1} | bounds={2}" -f $_.DeviceName, $_.Primary, $_.Bounds)
}
