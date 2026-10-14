using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

/// <summary>
/// Reads the live TCP/UDP tables (IPv4 + IPv6) together with the owning process id,
/// using the Windows IP Helper API. Read-only: this never changes any network state.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class IpHelperConnectionSource : IConnectionSource
{
    private delegate uint TableFetcher(IntPtr buffer, ref int size);

    public IReadOnlyList<ConnectionInfo> GetConnections()
    {
        var result = new List<ConnectionInfo>(512);
        ParseTcp4(Fetch((IntPtr b, ref int s) => NativeMethods.GetExtendedTcpTable(b, ref s, false, NativeMethods.AfInet, NativeMethods.TcpTableOwnerPidAll, 0)), result);
        ParseTcp6(Fetch((IntPtr b, ref int s) => NativeMethods.GetExtendedTcpTable(b, ref s, false, NativeMethods.AfInet6, NativeMethods.TcpTableOwnerPidAll, 0)), result);
        ParseUdp4(Fetch((IntPtr b, ref int s) => NativeMethods.GetExtendedUdpTable(b, ref s, false, NativeMethods.AfInet, NativeMethods.UdpTableOwnerPid, 0)), result);
        ParseUdp6(Fetch((IntPtr b, ref int s) => NativeMethods.GetExtendedUdpTable(b, ref s, false, NativeMethods.AfInet6, NativeMethods.UdpTableOwnerPid, 0)), result);
        return result;
    }

    // The table can grow between the "how big?" call and the "give me the data" call, so retry.
    private static byte[] Fetch(TableFetcher fetch)
    {
        int size = 0;
        uint rc = fetch(IntPtr.Zero, ref size);

        for (int attempt = 0; attempt < 8; attempt++)
        {
            if (rc != NativeMethods.ErrorInsufficientBuffer && rc != NativeMethods.NoError)
                throw new Win32Exception((int)rc);

            size += 4096;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                rc = fetch(buffer, ref size);
                if (rc == NativeMethods.NoError)
                {
                    var bytes = new byte[size];
                    Marshal.Copy(buffer, bytes, 0, size);
                    return bytes;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new Win32Exception((int)rc, "The connection table kept changing size; giving up after several attempts.");
    }

    // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (6 x uint32 = 24 bytes)
    private static void ParseTcp4(byte[] d, List<ConnectionInfo> into)
    {
        const int row = 24;
        uint count = BitConverter.ToUInt32(d, 0);
        for (int i = 0, o = 4; i < count && o + row <= d.Length; i++, o += row)
        {
            var state = (ConnectionState)BitConverter.ToUInt32(d, o);
            var local = new IPEndPoint(new IPAddress(d.AsSpan(o + 4, 4)), Port(BitConverter.ToUInt32(d, o + 8)));
            var remote = new IPEndPoint(new IPAddress(d.AsSpan(o + 12, 4)), Port(BitConverter.ToUInt32(d, o + 16)));
            int pid = (int)BitConverter.ToUInt32(d, o + 20);
            into.Add(new ConnectionInfo(Protocol.Tcp, local, remote, state, pid));
        }
    }

    // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid (56 bytes)
    private static void ParseTcp6(byte[] d, List<ConnectionInfo> into)
    {
        const int row = 56;
        uint count = BitConverter.ToUInt32(d, 0);
        for (int i = 0, o = 4; i < count && o + row <= d.Length; i++, o += row)
        {
            var local = new IPEndPoint(new IPAddress(d.AsSpan(o, 16), BitConverter.ToUInt32(d, o + 16)), Port(BitConverter.ToUInt32(d, o + 20)));
            var remote = new IPEndPoint(new IPAddress(d.AsSpan(o + 24, 16), BitConverter.ToUInt32(d, o + 40)), Port(BitConverter.ToUInt32(d, o + 44)));
            var state = (ConnectionState)BitConverter.ToUInt32(d, o + 48);
            int pid = (int)BitConverter.ToUInt32(d, o + 52);
            into.Add(new ConnectionInfo(Protocol.Tcp, local, remote, state, pid));
        }
    }

    // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid (12 bytes). UDP has no remote endpoint or state.
    private static void ParseUdp4(byte[] d, List<ConnectionInfo> into)
    {
        const int row = 12;
        uint count = BitConverter.ToUInt32(d, 0);
        for (int i = 0, o = 4; i < count && o + row <= d.Length; i++, o += row)
        {
            var local = new IPEndPoint(new IPAddress(d.AsSpan(o, 4)), Port(BitConverter.ToUInt32(d, o + 4)));
            int pid = (int)BitConverter.ToUInt32(d, o + 8);
            into.Add(new ConnectionInfo(Protocol.Udp, local, null, ConnectionState.None, pid));
        }
    }

    // MIB_UDP6ROW_OWNER_PID: localAddr[16], localScope, localPort, pid (28 bytes)
    private static void ParseUdp6(byte[] d, List<ConnectionInfo> into)
    {
        const int row = 28;
        uint count = BitConverter.ToUInt32(d, 0);
        for (int i = 0, o = 4; i < count && o + row <= d.Length; i++, o += row)
        {
            var local = new IPEndPoint(new IPAddress(d.AsSpan(o, 16), BitConverter.ToUInt32(d, o + 16)), Port(BitConverter.ToUInt32(d, o + 20)));
            int pid = (int)BitConverter.ToUInt32(d, o + 24);
            into.Add(new ConnectionInfo(Protocol.Udp, local, null, ConnectionState.None, pid));
        }
    }

    // Ports are stored in network byte order in the low 16 bits of a 32-bit field.
    private static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));
}
