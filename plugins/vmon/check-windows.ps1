$src = @'
using System;
using System.Runtime.InteropServices;
public class WR {
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder sb, int max);
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    public struct RECT { public int left, top, right, bottom; }
    public static string Dump() {
        var sb = new System.Text.StringBuilder();
        EnumWindows(delegate(IntPtr h, IntPtr l) {
            if (!IsWindowVisible(h)) return true;
            var t = new System.Text.StringBuilder(256);
            GetWindowText(h, t, 256);
            if (t.Length == 0) return true;
            RECT r; GetWindowRect(h, out r);
            uint pid; GetWindowThreadProcessId(h, out pid);
            sb.AppendLine(string.Format("{0} | pid={1} | ({2},{3})-({4},{5})", t.ToString().Substring(0, Math.Min(30, t.Length)), pid, r.left, r.top, r.right, r.bottom));
            return true;
        }, IntPtr.Zero);
        return sb.ToString();
    }
}
'@
Add-Type -TypeDefinition $src
[WR]::Dump() | Out-String | Write-Output
