using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace NetSentinel.Core;

/// <summary>
/// A set of remote addresses: IPv4 addresses, CIDR blocks (10.0.0.0/8) and ranges (1.2.3.4-1.2.3.9),
/// IPv6 addresses, CIDR blocks (2001:db8::/32) and ranges (fe80::1-fe80::ff).
/// Windows keywords (LocalSubnet, DNS, DHCP, DefaultGateway, WINS) are kept as typed.
/// Both IPv4 and IPv6 sets can be inverted (<see cref="Complement"/>). Sets with keywords cannot be inverted.
/// </summary>
public sealed class AddressSet
{
    private static readonly string[] Keywords = { "LocalSubnet", "DNS", "DHCP", "DefaultGateway", "WINS" };

    private readonly List<(uint Start, uint End)> _v4;
    private readonly Ipv6AddressSet _v6;
    private readonly List<string> _keywords;

    private AddressSet(List<(uint, uint)> v4, Ipv6AddressSet v6, List<string> keywords)
    {
        _v4 = v4;
        _v6 = v6;
        _keywords = keywords;
    }

    public static AddressSet Empty { get; } = new(new List<(uint, uint)>(), Ipv6AddressSet.Empty, new List<string>());

    /// <summary>Loopback, private, link-local, multicast and broadcast for both IPv4 and IPv6: traffic that stays on your machine or LAN.</summary>
    public static AddressSet LocalNetwork { get; } = new(Merge(new List<(uint, uint)>
    {
        (Ip("10.0.0.0"), Ip("10.255.255.255")),
        (Ip("127.0.0.0"), Ip("127.255.255.255")),
        (Ip("169.254.0.0"), Ip("169.254.255.255")),
        (Ip("172.16.0.0"), Ip("172.31.255.255")),
        (Ip("192.168.0.0"), Ip("192.168.255.255")),
        (Ip("224.0.0.0"), Ip("255.255.255.255")),
    }), Ipv6AddressSet.LocalNetwork, new List<string>());

    public bool IsEmpty => _v4.Count == 0 && _v6.IsEmpty && _keywords.Count == 0;

    /// <summary>True if the set contains Windows keywords, which cannot be inverted.</summary>
    public bool HasKeywords => _keywords.Count > 0;

    /// <summary>True if the set contains IPv6 addresses or keywords.</summary>
    public bool HasNonIpv4 => !_v6.IsEmpty || _keywords.Count > 0;

    public bool HasIpv4 => _v4.Count > 0;

    public bool HasIpv6 => !_v6.IsEmpty;

    public IReadOnlyList<(uint Start, uint End)> V4Ranges => _v4;

    public Ipv6AddressSet V6 => _v6;

    public IReadOnlyList<string> Other => _keywords;

    public static bool TryParse(string? text, out AddressSet set, out string error)
    {
        set = Empty;
        error = "";
        if (string.IsNullOrWhiteSpace(text)) return true;

        var v4 = new List<(uint, uint)>();
        var v6Ranges = new List<(UInt128, UInt128)>();
        var keywords = new List<string>();

        foreach (var token in text.Split(new[] { ',', ';' }, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var keyword = Keywords.FirstOrDefault(k => k.Equals(token, StringComparison.OrdinalIgnoreCase));
            if (keyword is not null) { keywords.Add(keyword); continue; }

            if (token.Contains(':'))
            {
                if (Ipv6AddressSet.TryParseToken(token, out var v6Range, out string v6Err))
                {
                    v6Ranges.Add(v6Range);
                    continue;
                }
                error = v6Err;
                return false;
            }

            if (!TryParseV4Token(token, out var range))
            {
                error = $"'{token}' is not a valid address. Use an IPv4 address (1.2.3.4), a block (10.0.0.0/8) or a range (1.2.3.4-1.2.3.9).";
                return false;
            }
            v4.Add(range);
        }

        set = new AddressSet(
            Merge(v4),
            new Ipv6AddressSet(Ipv6AddressSet.Merge(v6Ranges)),
            keywords.Distinct(StringComparer.OrdinalIgnoreCase).ToList());
        return true;
    }

    private static bool TryParseV4Token(string token, out (uint, uint) range)
    {
        range = default;

        int dash = token.IndexOf('-');
        if (dash > 0)
        {
            if (!TryIp(token[..dash].Trim(), out uint a) || !TryIp(token[(dash + 1)..].Trim(), out uint b) || b < a) return false;
            range = (a, b);
            return true;
        }

        int slash = token.IndexOf('/');
        if (slash > 0)
        {
            if (!TryIp(token[..slash].Trim(), out uint baseIp)
                || !int.TryParse(token[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out int bits) || bits is < 0 or > 32)
                return false;

            uint mask = bits == 0 ? 0 : uint.MaxValue << (32 - bits);
            range = (baseIp & mask, (baseIp & mask) | ~mask);
            return true;
        }

        if (!TryIp(token, out uint single)) return false;
        range = (single, single);
        return true;
    }

    private static bool TryIp(string s, out uint value)
    {
        value = 0;
        var parts = s.Split('.');
        if (parts.Length != 4) return false;
        foreach (var part in parts)
        {
            if (!byte.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out byte b)) return false;
            value = (value << 8) | b;
        }
        return true;
    }

    private static uint Ip(string s) => TryIp(s, out uint v) ? v : throw new ArgumentException(s);

    private static string Format(uint ip) => $"{ip >> 24}.{(ip >> 16) & 255}.{(ip >> 8) & 255}.{ip & 255}";

    private static List<(uint, uint)> Merge(List<(uint Start, uint End)> ranges)
    {
        var merged = new List<(uint, uint)>();
        foreach (var (s, e) in ranges.OrderBy(r => r.Start))
        {
            if (merged.Count > 0 && (ulong)s <= (ulong)merged[^1].Item2 + 1)
                merged[^1] = (merged[^1].Item1, Math.Max(merged[^1].Item2, e));
            else
                merged.Add((s, e));
        }
        return merged;
    }

    public AddressSet Union(AddressSet other) =>
        new(Merge(_v4.Concat(other._v4).ToList()), _v6.Union(other._v6), _keywords.Concat(other._keywords).Distinct(StringComparer.OrdinalIgnoreCase).ToList());

    /// <summary>Every address NOT in this set across IPv4 and IPv6. Throws if the set contains Windows keywords.</summary>
    public AddressSet Complement()
    {
        if (HasKeywords) throw new InvalidOperationException("Address sets with Windows keywords (e.g. LocalSubnet) cannot be inverted.");

        var resultV4 = new List<(uint, uint)>();
        ulong next = 0;
        foreach (var (s, e) in _v4)
        {
            if (s > next) resultV4.Add(((uint)next, s - 1));
            next = (ulong)e + 1;
        }
        if (next <= uint.MaxValue) resultV4.Add(((uint)next, uint.MaxValue));

        var resultV6 = _v6.Complement();

        return new AddressSet(resultV4, resultV6, new List<string>());
    }

    public bool Contains(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            uint v = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            return _v4.Any(r => v >= r.Start && v <= r.End);
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return _v6.Contains(ip);
        }

        return false;
    }

    /// <summary>Normalised text for Windows Firewall, e.g. "1.2.3.4,10.0.0.0-10.255.255.255,fe80::1".</summary>
    public string ToFirewallString()
    {
        var parts = new List<string>();
        foreach (var r in _v4)
        {
            parts.Add(r.Start == r.End ? Format(r.Start) : $"{Format(r.Start)}-{Format(r.End)}");
        }
        if (!_v6.IsEmpty)
        {
            parts.Add(_v6.ToFirewallString());
        }
        parts.AddRange(_keywords);
        return string.Join(",", parts);
    }

    public override string ToString() => ToFirewallString();
}
