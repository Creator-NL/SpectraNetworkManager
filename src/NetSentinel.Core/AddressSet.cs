using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace NetSentinel.Core;

/// <summary>
/// A set of remote addresses: IPv4 addresses, CIDR blocks (10.0.0.0/8) and ranges (1.2.3.4-1.2.3.9).
/// IPv6 addresses and Windows keywords (LocalSubnet, DNS, DHCP, DefaultGateway, WINS) are kept as typed.
/// Only IPv4 sets can be inverted (<see cref="Complement"/>).
/// </summary>
public sealed class AddressSet
{
    private static readonly string[] Keywords = { "LocalSubnet", "DNS", "DHCP", "DefaultGateway", "WINS" };

    private readonly List<(uint Start, uint End)> _v4;
    private readonly List<string> _other;

    private AddressSet(List<(uint, uint)> v4, List<string> other)
    {
        _v4 = v4;
        _other = other;
    }

    public static AddressSet Empty { get; } = new(new List<(uint, uint)>(), new List<string>());

    /// <summary>Loopback, private, link-local, multicast and broadcast: traffic that stays on your machine or LAN.</summary>
    public static AddressSet LocalNetwork { get; } = new(Merge(new List<(uint, uint)>
    {
        (Ip("10.0.0.0"), Ip("10.255.255.255")),
        (Ip("127.0.0.0"), Ip("127.255.255.255")),
        (Ip("169.254.0.0"), Ip("169.254.255.255")),
        (Ip("172.16.0.0"), Ip("172.31.255.255")),
        (Ip("192.168.0.0"), Ip("192.168.255.255")),
        (Ip("224.0.0.0"), Ip("255.255.255.255")),
    }), new List<string>());

    public bool IsEmpty => _v4.Count == 0 && _other.Count == 0;

    /// <summary>True if the set contains IPv6 addresses or keywords, which cannot be inverted.</summary>
    public bool HasNonIpv4 => _other.Count > 0;

    public static bool TryParse(string? text, out AddressSet set, out string error)
    {
        set = Empty;
        error = "";
        if (string.IsNullOrWhiteSpace(text)) return true;

        var v4 = new List<(uint, uint)>();
        var other = new List<string>();

        foreach (var token in text.Split(new[] { ',', ';' }, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var keyword = Keywords.FirstOrDefault(k => k.Equals(token, StringComparison.OrdinalIgnoreCase));
            if (keyword is not null) { other.Add(keyword); continue; }

            if (token.Contains(':'))
            {
                string addr = token.Split('/')[0];
                bool prefixOk = !token.Contains('/') || (int.TryParse(token.Split('/')[1], NumberStyles.None, CultureInfo.InvariantCulture, out int p) && p is >= 0 and <= 128);
                if (IPAddress.TryParse(addr, out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6 && prefixOk) { other.Add(token); continue; }
                error = $"'{token}' is not a valid IPv6 address.";
                return false;
            }

            if (!TryParseV4Token(token, out var range))
            {
                error = $"'{token}' is not a valid address. Use an IPv4 address (1.2.3.4), a block (10.0.0.0/8) or a range (1.2.3.4-1.2.3.9).";
                return false;
            }
            v4.Add(range);
        }

        set = new AddressSet(Merge(v4), other.Distinct(StringComparer.OrdinalIgnoreCase).ToList());
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
        // Require four dotted decimal parts: IPAddress.TryParse would also accept things like "1" or "1.2".
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
        new(Merge(_v4.Concat(other._v4).ToList()), _other.Concat(other._other).Distinct(StringComparer.OrdinalIgnoreCase).ToList());

    /// <summary>Every IPv4 address NOT in this set. Throws if the set contains IPv6 addresses or keywords.</summary>
    public AddressSet Complement()
    {
        if (HasNonIpv4) throw new InvalidOperationException("Only IPv4 address sets can be inverted.");

        var result = new List<(uint, uint)>();
        ulong next = 0;
        foreach (var (s, e) in _v4)
        {
            if (s > next) result.Add(((uint)next, s - 1));
            next = (ulong)e + 1;
        }
        if (next <= uint.MaxValue) result.Add(((uint)next, uint.MaxValue));
        return new AddressSet(result, new List<string>());
    }

    public bool Contains(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        uint v = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        return _v4.Any(r => v >= r.Start && v <= r.End);
    }

    /// <summary>Normalised text for Windows Firewall, e.g. "1.2.3.4,10.0.0.0-10.255.255.255,fe80::1".</summary>
    public string ToFirewallString() => string.Join(",",
        _v4.Select(r => r.Start == r.End ? Format(r.Start) : $"{Format(r.Start)}-{Format(r.End)}").Concat(_other));

    public override string ToString() => ToFirewallString();
}
