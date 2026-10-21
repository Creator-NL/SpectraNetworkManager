using System.Runtime.InteropServices;

namespace SpectraNetworkManager.Ui;

internal static class NativeMethods
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FLASHWINFO
    {
        public uint cbSize;
        public IntPtr hwnd;
        public uint dwFlags;
        public uint uCount;
        public uint dwTimeout;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlashWindowEx(ref FLASHWINFO info);

    private const uint FlashAll = 3;          // caption + taskbar button
    private const uint FlashUntilForeground = 12;

    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_NOACTIVATE = 0x08000000;
    private const int WS_EX_TOOLWINDOW = 0x00000080;

    [DllImport("user32.dll", EntryPoint = "GetWindowLongW", SetLastError = true)]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "SetWindowLongW", SetLastError = true)]
    private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

    /// <summary>Configures a popup window so it does not steal keyboard focus from the active foreground application.</summary>
    public static void SetNoActivate(IntPtr hwnd)
    {
        try
        {
            if (IntPtr.Size == 8)
            {
                var val = GetWindowLongPtr(hwnd, GWL_EXSTYLE).ToInt64();
                val |= WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW;
                SetWindowLongPtr(hwnd, GWL_EXSTYLE, new IntPtr(val));
            }
            else
            {
                var val = GetWindowLong(hwnd, GWL_EXSTYLE);
                val |= WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW;
                SetWindowLong(hwnd, GWL_EXSTYLE, val);
            }
        }
        catch { /* best effort */ }
    }

    /// <summary>Makes the taskbar button flash until the user switches to the window.</summary>
    public static void FlashUntilActivated(IntPtr windowHandle)
    {
        var info = new FLASHWINFO
        {
            cbSize = (uint)Marshal.SizeOf<FLASHWINFO>(),
            hwnd = windowHandle,
            dwFlags = FlashAll | FlashUntilForeground,
            uCount = uint.MaxValue,
            dwTimeout = 0,
        };
        FlashWindowEx(ref info);
    }
}
