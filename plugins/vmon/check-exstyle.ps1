$src = @'
using System;
using System.Runtime.InteropServices;
public class XS {
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int idx);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder sb, int max);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
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
            if (r.left < 0 || r.top < 0) {
                int ex = GetWindowLong(h, -20); // GWL_EXSTYLE
                sb.AppendLine(string.Format("{0} | toolwindow={1} | ({2},{3})", t.ToString().Substring(0, Math.Min(30, t.Length)), (ex & 0x80) != 0, r.left, r.top));
            }
            return true;
        }, IntPtr.Zero);
        return sb.ToString();
    }
}
'@
Add-Type -TypeDefinition $src
[XS]::Dump() | Out-String | Write-Output
