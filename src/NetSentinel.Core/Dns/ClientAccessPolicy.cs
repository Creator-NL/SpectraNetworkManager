using System.Net;

namespace NetSentinel.Sinkhole;

/// <summary>
/// Determines which client IP addresses are allowed to query this DNS server.
/// By default, only loopback and private/local network ranges are permitted to prevent the server
/// from acting as an open DNS resolver if bound to 0.0.0.0 on a machine with public exposure.
/// </summary>
public sealed class ClientAccessPolicy
{
    private static readonly IReadOnlyList<IPNetwork> DefaultPrivateIpv4Networks = new[]
    {
        IPNetwork.Parse("127.0.0.0/8"),      // Loopback
        IPNetwork.Parse("10.0.0.0/8"),       // RFC 1918 Private
        IPNetwork.Parse("172.16.0.0/12"),    // RFC 1918 Private (172.16.0.0 - 172.31.255.255)
        IPNetwork.Parse("192.168.0.0/16"),   // RFC 1918 Private
        IPNetwork.Parse("169.254.0.0/16"),   // RFC 3927 Link-Local
        IPNetwork.Parse("100.64.0.0/10"),    // RFC 6598 Shared Address Space / CGNAT / Tailscale
    };

    private static readonly IReadOnlyList<IPNetwork> DefaultPrivateIpv6Networks = new[]
    {
        IPNetwork.Parse("::1/128"),          // Loopback
        IPNetwork.Parse("fc00::/7"),         // RFC 4193 Unique Local Address (ULA)
        IPNetwork.Parse("fe80::/10"),        // RFC 4291 Link-Local
    };

    private readonly List<IPNetwork> _ipv4Networks = new();
    private readonly List<IPNetwork> _ipv6Networks = new();

    public ClientAccessPolicy(bool restrictToLocal = true, IEnumerable<string>? customAllowedRanges = null)
    {
        RestrictToLocal = restrictToLocal;

        if (restrictToLocal)
        {
            _ipv4Networks.AddRange(DefaultPrivateIpv4Networks);
            _ipv6Networks.AddRange(DefaultPrivateIpv6Networks);
        }

        if (customAllowedRanges is not null)
        {
            foreach (var range in customAllowedRanges)
            {
                if (IPNetwork.TryParse(range.Trim(), out var net))
                {
                    if (net.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        _ipv4Networks.Add(net);
                    else if (net.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        _ipv6Networks.Add(net);
                }
            }
        }
    }

    public bool RestrictToLocal { get; }

    /// <summary>
    /// Checks whether the given client address is allowed to query the server.
    /// </summary>
    public bool IsAllowed(IPAddress clientAddress)
    {
        if (!RestrictToLocal) return true;

        if (clientAddress.IsIPv4MappedToIPv6)
            clientAddress = clientAddress.MapToIPv4();

        if (IPAddress.IsLoopback(clientAddress))
            return true;

        if (clientAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            for (int i = 0; i < _ipv4Networks.Count; i++)
            {
                if (_ipv4Networks[i].Contains(clientAddress))
                    return true;
            }
            return false;
        }

        if (clientAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            for (int i = 0; i < _ipv6Networks.Count; i++)
            {
                if (_ipv6Networks[i].Contains(clientAddress))
                    return true;
            }
            return false;
        }

        return false;
    }
}
