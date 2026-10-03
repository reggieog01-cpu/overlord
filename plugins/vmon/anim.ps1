$src = @'
using System;
using System.Runtime.InteropServices;
public class MV {
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int ht, bool repaint);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    public static void MovePid(uint targetPid, int x, int y, int w, int ht) {
        EnumWindows(delegate(IntPtr h, IntPtr l) {
            uint pid; GetWindowThreadProcessId(h, out pid);
            if (pid == targetPid && IsWindowVisible(h)) { MoveWindow(h, x, y, w, ht, true); }
            return true;
        }, IntPtr.Zero);
    }
}
'@
Add-Type -TypeDefinition $src
$p = Start-Process notepad -PassThru
Start-Sleep -Seconds 1
[MV]::MovePid($p.Id, 30060, 30060, 800, 600)
Start-Sleep -Seconds 12
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
