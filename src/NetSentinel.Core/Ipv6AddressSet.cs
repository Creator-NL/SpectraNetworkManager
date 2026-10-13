using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace NetSentinel.Core;

/// <summary>
/// A set of IPv6 remote addresses, CIDR blocks (2001:db8::/32) and ranges (fe80::1-fe80::ff).
/// Operates on 128-bit integers (UInt128), supporting union, merge and inversion (Complement).
/// </summary>
public sealed class Ipv6AddressSet
{
    private readonly List<(UInt128 Start, UInt128 End)> _ranges;

    public Ipv6AddressSet(List<(UInt128 Start, UInt128 End)> ranges)
    {
        _ranges = ranges;
    }

    public static Ipv6AddressSet Empty { get; } = new(new List<(UInt128, UInt128)>());

    /// <summary>
    /// Loopback (::1/128), Link-local (fe80::/10), Unique Local Addresses (fc00::/7) and Multicast (ff00::/8).
    /// </summary>
    public static Ipv6AddressSet LocalNetwork { get; } = new(Merge(new List<(UInt128, UInt128)>
    {
        // Loopback ::1/128
        (UInt128.One, UInt128.One),
        // Link-local fe80::/10 (fe80:: - febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff)
        CidrRange(Ip("fe80::"), 10),
        // Unique Local fc00::/7 (fc00:: - fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff)
        CidrRange(Ip("fc00::"), 7),
        // Multicast ff00::/8 (ff00:: - ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff)
        CidrRange(Ip("ff00::"), 8),
    }));

    public bool IsEmpty => _ranges.Count == 0;

    public IReadOnlyList<(UInt128 Start, UInt128 End)> Ranges => _ranges;

    public static bool TryParse(string? text, out Ipv6AddressSet set, out string error)
    {
        set = Empty;
        error = "";
        if (string.IsNullOrWhiteSpace(text)) return true;

        var ranges = new List<(UInt128, UInt128)>();

        foreach (var token in text.Split(new[] { ',', ';' }, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TryParseToken(token, out var range, out error))
            {
                return false;
            }
            ranges.Add(range);
        }

        set = new Ipv6AddressSet(Merge(ranges));
        return true;
    }

    public static bool TryParseToken(string token, out (UInt128 Start, UInt128 End) range, out string error)
    {
        range = default;
        error = "";

        // Check for range: addr1-addr2
        int dash = token.IndexOf('-');
        if (dash > 0)
        {
            string s1 = token[..dash].Trim();
            string s2 = token[(dash + 1)..].Trim();
            if (!TryIp(s1, out var a) || !TryIp(s2, out var b) || b < a)
            {
                error = $"'{token}' is not a valid IPv6 range.";
                return false;
            }
            range = (a, b);
            return true;
        }

        // Check for CIDR: addr/prefix
        int slash = token.IndexOf('/');
        if (slash > 0)
        {
            string sAddr = token[..slash].Trim();
            string sBits = token[(slash + 1)..].Trim();
            if (!TryIp(sAddr, out var baseIp) || !int.TryParse(sBits, NumberStyles.None, CultureInfo.InvariantCulture, out int bits) || bits is < 0 or > 128)
            {
                error = $"'{token}' is not a valid IPv6 CIDR block.";
                return false;
            }

            range = CidrRange(baseIp, bits);
            return true;
        }

        // Single address
        if (!TryIp(token, out var single))
        {
            error = $"'{token}' is not a valid IPv6 address.";
            return false;
        }

        range = (single, single);
        return true;
    }

    private static (UInt128 Start, UInt128 End) CidrRange(UInt128 baseIp, int bits)
    {
        if (bits == 0) return (UInt128.Zero, UInt128.MaxValue);
        if (bits == 128) return (baseIp, baseIp);

        UInt128 mask = UInt128.MaxValue << (128 - bits);
        return (baseIp & mask, (baseIp & mask) | ~mask);
    }

    public static bool TryIp(string s, out UInt128 value)
    {
        value = UInt128.Zero;
        if (!IPAddress.TryParse(s, out var ip) || ip.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[16];
        if (!ip.TryWriteBytes(bytes, out _)) return false;

        ulong hi = BinaryPrimitives.ReadUInt64BigEndian(bytes[..8]);
        ulong lo = BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]);
        value = ((UInt128)hi << 64) | lo;
        return true;
    }

    public static UInt128 Ip(string s) => TryIp(s, out var v) ? v : throw new ArgumentException($"Invalid IPv6 address: {s}");

    public static string Format(UInt128 val)
    {
        Span<byte> bytes = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(bytes[..8], (ulong)(val >> 64));
        BinaryPrimitives.WriteUInt64BigEndian(bytes[8..], (ulong)val);
        return new IPAddress(bytes).ToString();
    }

    public static List<(UInt128 Start, UInt128 End)> Merge(List<(UInt128 Start, UInt128 End)> ranges)
    {
        var merged = new List<(UInt128 Start, UInt128 End)>();
        foreach (var (s, e) in ranges.OrderBy(r => r.Start))
        {
            if (merged.Count > 0 && s <= merged[^1].End + 1 && (merged[^1].End != UInt128.MaxValue))
            {
                var prev = merged[^1];
                merged[^1] = (prev.Start, e > prev.End ? e : prev.End);
            }
            else
            {
                merged.Add((s, e));
            }
        }
        return merged;
    }

    public Ipv6AddressSet Union(Ipv6AddressSet other)
    {
        return new Ipv6AddressSet(Merge(_ranges.Concat(other._ranges).ToList()));
    }

    /// <summary>
    /// Every IPv6 address NOT in this set across the entire 128-bit address space.
    /// </summary>
    public Ipv6AddressSet Complement()
    {
        var result = new List<(UInt128, UInt128)>();
        UInt128 next = UInt128.Zero;

        foreach (var (s, e) in _ranges)
        {
            if (s > next)
            {
                result.Add((next, s - 1));
            }

            if (e == UInt128.MaxValue)
            {
                next = UInt128.MaxValue;
                break;
            }
            next = e + 1;
        }

        if (next < UInt128.MaxValue || (next == UInt128.MaxValue && (_ranges.Count == 0 || _ranges[^1].End < UInt128.MaxValue)))
        {
            result.Add((next, UInt128.MaxValue));
        }

        return new Ipv6AddressSet(result);
    }

    public bool Contains(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetworkV6) return false;

        Span<byte> bytes = stackalloc byte[16];
        if (!ip.TryWriteBytes(bytes, out _)) return false;

        ulong hi = BinaryPrimitives.ReadUInt64BigEndian(bytes[..8]);
        ulong lo = BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]);
        UInt128 v = ((UInt128)hi << 64) | lo;

        return _ranges.Any(r => v >= r.Start && v <= r.End);
    }

    public string ToFirewallString()
    {
        return string.Join(",", _ranges.Select(r => r.Start == r.End ? Format(r.Start) : $"{Format(r.Start)}-{Format(r.End)}"));
    }

    public override string ToString() => ToFirewallString();
}
