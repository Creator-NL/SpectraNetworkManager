using System.Runtime.InteropServices;

namespace NetSentinel.Ui;

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
