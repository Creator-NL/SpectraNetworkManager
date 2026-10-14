using System.Net;
using System.Net.Sockets;

namespace SpectraNetworkManager.Core;

/// <summary>Human-readable formatting shared by every front end (WPF app, console, later the web UI).</summary>
public static class Display
{
    public static string Endpoint(IPEndPoint? ep)
    {
        if (ep is null) return "*";
        if (ep.Port == 0 && (ep.Address.Equals(IPAddress.Any) || ep.Address.Equals(IPAddress.IPv6Any))) return "*";
        return ep.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{ep.Address}]:{ep.Port}" : $"{ep.Address}:{ep.Port}";
    }

    public static string State(ConnectionState s) => s switch
    {
        ConnectionState.None => "\u2014",
        ConnectionState.Closed => "CLOSED",
        ConnectionState.Listen => "LISTEN",
        ConnectionState.SynSent => "SYN_SENT",
        ConnectionState.SynReceived => "SYN_RCVD",
        ConnectionState.Established => "ESTABLISHED",
        ConnectionState.FinWait1 => "FIN_WAIT1",
        ConnectionState.FinWait2 => "FIN_WAIT2",
        ConnectionState.CloseWait => "CLOSE_WAIT",
        ConnectionState.Closing => "CLOSING",
        ConnectionState.LastAck => "LAST_ACK",
        ConnectionState.TimeWait => "TIME_WAIT",
        ConnectionState.DeleteTcb => "DELETE_TCB",
        _ => s.ToString().ToUpperInvariant(),
    };

    /// <summary>True for connection states that are just teardown noise (TIME_WAIT and friends).</summary>
    public static bool IsTeardownNoise(ConnectionState s) =>
        s is ConnectionState.TimeWait or ConnectionState.Closed or ConnectionState.DeleteTcb
          or ConnectionState.Closing or ConnectionState.LastAck or ConnectionState.FinWait1 or ConnectionState.FinWait2;

    /// <summary>True for addresses that never leave your own machine or LAN (loopback, private, link-local, unspecified).</summary>
    public static bool IsLocalAddress(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || b[0] >= 224;                         // multicast / reserved
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast
                || (b[0] & 0xFE) == 0xFC;               // unique local fc00::/7
        }
        return false;
    }

    /// <summary>Formats a byte count into a compact human-readable string (e.g. 1.2 MB, 450 KB, 12 B).</summary>
    public static string Bytes(long bytes)
    {
        if (bytes < 0) bytes = 0;
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double val = bytes;
        int i = 0;
        while (val >= 1024 && i < units.Length - 1)
        {
            val /= 1024;
            i++;
        }
        return i == 0 ? $"{bytes.ToString("N0", System.Globalization.CultureInfo.InvariantCulture)} B" : $"{val.ToString("F1", System.Globalization.CultureInfo.InvariantCulture)} {units[i]}";
    }

    /// <summary>Formats transfer speed into a compact human-readable string (e.g. 1.2 MB/s, 45 KB/s).</summary>
    public static string Rate(long bytesPerSec)
    {
        if (bytesPerSec <= 0) return "\u2014";
        return $"{Bytes(bytesPerSec)}/s";
    }
}
