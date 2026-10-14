using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

/// <summary>
/// Programmatically terminates active TCP connections on Windows using SetTcpEntry with MIB_TCP_STATE_DELETE_TCB (12).
/// Requires Administrator or LocalSystem privileges to tear down sockets.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TcpConnectionTerminator : IConnectionTerminator
{
    public const uint MibTcpStateDeleteTcb = 12;

    public int TerminateConnectionsForPid(int pid)
    {
        if (pid <= 0) return 0;
        int closed = 0;
        var rows = GetTcp4Rows();
        foreach (var r in rows)
        {
            if (r.OwningPid == pid && IsActiveState(r.State))
            {
                if (CloseRow(r)) closed++;
            }
        }
        return closed;
    }

    public int TerminateConnectionsForProgram(string pathOrName)
    {
        if (string.IsNullOrWhiteSpace(pathOrName)) return 0;

        var targetPids = new HashSet<int>();
        var resolver = new ProcessResolver();

        var rows = GetTcp4Rows();
        foreach (var r in rows)
        {
            if (r.OwningPid > 0 && IsActiveState(r.State))
            {
                var proc = resolver.Resolve(r.OwningPid);
                if (string.Equals(proc.Path, pathOrName, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(proc.Name, pathOrName, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(Path.GetFileName(proc.Path), Path.GetFileName(pathOrName), StringComparison.OrdinalIgnoreCase))
                {
                    targetPids.Add(r.OwningPid);
                }
            }
        }

        int totalClosed = 0;
        foreach (var pid in targetPids)
        {
            totalClosed += TerminateConnectionsForPid(pid);
        }
        return totalClosed;
    }

    public bool TerminateConnection(IPEndPoint local, IPEndPoint remote)
    {
        if (local.AddressFamily != AddressFamily.InterNetwork || remote.AddressFamily != AddressFamily.InterNetwork)
            return false;

        var rows = GetTcp4Rows();
        foreach (var r in rows)
        {
            if (r.Local.Equals(local) && r.Remote.Equals(remote))
            {
                return CloseRow(r);
            }
        }
        return false;
    }

    /// <summary>
    /// Kills the target process and its child process tree.
    /// </summary>
    public static bool KillProcess(int pid)
    {
        if (pid <= 0) return false;
        try
        {
            using var p = Process.GetProcessById(pid);
            p.Kill(entireProcessTree: true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool CloseRow(RawTcp4Row r)
    {
        try
        {
            var row = new NativeMethods.MibTcpRow
            {
                State = MibTcpStateDeleteTcb,
                LocalAddr = r.RawLocalAddr,
                LocalPort = r.RawLocalPort,
                RemoteAddr = r.RawRemoteAddr,
                RemotePort = r.RawRemotePort,
            };
            uint rc = NativeMethods.SetTcpEntry(ref row);
            return rc == NativeMethods.NoError;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsActiveState(uint state) =>
        state is 3 or 4 or 5 or 6 or 7 or 8 or 9 or 10; // SynSent, SynRcvd, Established, FinWait1, FinWait2, CloseWait, Closing, LastAck

    private sealed record RawTcp4Row(
        uint State,
        uint RawLocalAddr,
        uint RawLocalPort,
        uint RawRemoteAddr,
        uint RawRemotePort,
        int OwningPid,
        IPEndPoint Local,
        IPEndPoint Remote);

    private static List<RawTcp4Row> GetTcp4Rows()
    {
        var list = new List<RawTcp4Row>();
        int size = 0;
        uint rc = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, NativeMethods.AfInet, NativeMethods.TcpTableOwnerPidAll, 0);
        if (rc != NativeMethods.ErrorInsufficientBuffer && rc != NativeMethods.NoError) return list;

        for (int attempt = 0; attempt < 5; attempt++)
        {
            size += 4096;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                rc = NativeMethods.GetExtendedTcpTable(buffer, ref size, false, NativeMethods.AfInet, NativeMethods.TcpTableOwnerPidAll, 0);
                if (rc == NativeMethods.NoError)
                {
                    byte[] d = new byte[size];
                    Marshal.Copy(buffer, d, 0, size);
                    uint count = BitConverter.ToUInt32(d, 0);
                    const int rowLen = 24;
                    for (int i = 0, o = 4; i < count && o + rowLen <= d.Length; i++, o += rowLen)
                    {
                        uint state = BitConverter.ToUInt32(d, o);
                        uint rawLocalAddr = BitConverter.ToUInt32(d, o + 4);
                        uint rawLocalPort = BitConverter.ToUInt32(d, o + 8);
                        uint rawRemoteAddr = BitConverter.ToUInt32(d, o + 12);
                        uint rawRemotePort = BitConverter.ToUInt32(d, o + 16);
                        int pid = (int)BitConverter.ToUInt32(d, o + 20);

                        var localEp = new IPEndPoint(new IPAddress(d.AsSpan(o + 4, 4)), Port(rawLocalPort));
                        var remoteEp = new IPEndPoint(new IPAddress(d.AsSpan(o + 12, 4)), Port(rawRemotePort));

                        list.Add(new RawTcp4Row(state, rawLocalAddr, rawLocalPort, rawRemoteAddr, rawRemotePort, pid, localEp, remoteEp));
                    }
                    return list;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return list;
    }

    private static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));
}
