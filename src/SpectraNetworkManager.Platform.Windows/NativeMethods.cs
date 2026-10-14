using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace SpectraNetworkManager.Platform.Windows;

[SupportedOSPlatform("windows")]
internal static class NativeMethods
{
    internal const int AfInet = 2;
    internal const int AfInet6 = 23;

    // TCP_TABLE_CLASS / UDP_TABLE_CLASS values we need.
    internal const int TcpTableOwnerPidAll = 5;
    internal const int UdpTableOwnerPid = 1;

    internal const uint NoError = 0;
    internal const uint ErrorInsufficientBuffer = 122;

    internal const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf, int tableClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    internal struct MibTcpRow
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint SetTcpEntry(ref MibTcpRow pTcpRow);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder exeName, ref int size);
}
