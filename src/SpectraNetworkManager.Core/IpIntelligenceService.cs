using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace SpectraNetworkManager.Core;

public sealed record IpIntelligenceInfo(
    string Ip,
    string CountryCode,
    string CountryName,
    string Asn,
    string Organization,
    string ScopeCategory,
    bool IsPrivateOrLocal)
{
    public string Category => ScopeCategory;
    public bool IsPublicRoutable => !IsPrivateOrLocal;

    public string ShortDisplay
    {
        get
        {
            if (IsPrivateOrLocal) return ScopeCategory;
            if (!string.IsNullOrWhiteSpace(CountryCode) && !string.IsNullOrWhiteSpace(Organization))
            {
                string asnPart = !string.IsNullOrWhiteSpace(Asn) ? $" ({Asn})" : "";
                return $"{CountryCode} · {Organization}{asnPart}";
            }
            if (!string.IsNullOrWhiteSpace(Organization))
                return !string.IsNullOrWhiteSpace(Asn) ? $"{Organization} ({Asn})" : Organization;
            if (!string.IsNullOrWhiteSpace(CountryCode))
                return $"{CountryCode} · {CountryName}";
            return ScopeCategory;
        }
    }
}

/// <summary>
/// Provides instant offline IP classification, well-known ASN/Organization mapping,
/// and cached remote IP threat lookup URLs (AbuseIPDB, Shodan, VirusTotal).
/// </summary>
public sealed class IpIntelligenceService
{
    private sealed record KnownPrefix(IPNetwork Network, string CountryCode, string CountryName, string Asn, string Organization, string Category);

    private static readonly List<KnownPrefix> KnownPrefixes = BuildKnownPrefixes();

    private readonly ConcurrentDictionary<string, IpIntelligenceInfo> _cache = new(StringComparer.OrdinalIgnoreCase);

    public IpIntelligenceInfo Analyze(IPAddress? address) => Inspect(address);

    public IpIntelligenceInfo Inspect(IPAddress? address)
    {
        if (address is null)
            return new IpIntelligenceInfo("*", "", "", "", "Unspecified", "Local / Unbound", true);

        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        string key = address.ToString();
        if (_cache.TryGetValue(key, out var cached))
            return cached;

        var info = ClassifyOffline(address, key);
        _cache[key] = info;
        return info;
    }

    public static string GetAbuseIpDbUrl(IPAddress address)
    {
        var clean = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        return $"https://www.abuseipdb.com/check/{Uri.EscapeDataString(clean.ToString())}";
    }

    public static string GetAbuseIpDbUrl(string ipText) =>
        $"https://www.abuseipdb.com/check/{Uri.EscapeDataString((ipText ?? "").Trim())}";

    public static string GetShodanUrl(IPAddress address)
    {
        var clean = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        return $"https://www.shodan.io/host/{Uri.EscapeDataString(clean.ToString())}";
    }

    public static string GetShodanUrl(string ipText) =>
        $"https://www.shodan.io/host/{Uri.EscapeDataString((ipText ?? "").Trim())}";

    public static bool IsPublicInternetIp(IPAddress? address)
    {
        if (address is null) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return !ClassifyOffline(address, address.ToString()).IsPrivateOrLocal;
    }

    private static IpIntelligenceInfo ClassifyOffline(IPAddress address, string ipText)
    {
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            return new IpIntelligenceInfo(ipText, "LOCAL", "This PC", "Loopback", "Localhost (This PC)", "Local Loopback", true);
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = address.GetAddressBytes();
            // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if (b[0] == 10 ||
                (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                (b[0] == 192 && b[1] == 168))
            {
                return new IpIntelligenceInfo(ipText, "LAN", "Local Network", "RFC1918", "Home / Private LAN", "Local Network (LAN)", true);
            }

            // 169.254.0.0/16 Link-local
            if (b[0] == 169 && b[1] == 254)
            {
                return new IpIntelligenceInfo(ipText, "LINK", "Link-Local", "APIPA", "Link-Local Auto-IP", "Link-Local", true);
            }

            // 100.64.0.0/10 CGNAT / Tailscale
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
            {
                return new IpIntelligenceInfo(ipText, "VPN", "Carrier NAT / VPN", "RFC6598", "Tailscale / CGNAT Mesh", "VPN / CGNAT", true);
            }

            // 224.0.0.0/4 Multicast & 255.255.255.255 Broadcast
            if (b[0] >= 224)
            {
                return new IpIntelligenceInfo(ipText, "LAN", "Local Broadcast", "Multicast", "LAN Discovery / Multicast", "LAN Multicast", true);
            }
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal)
            {
                return new IpIntelligenceInfo(ipText, "LAN", "Local IPv6", "Link-Local", "Local Network (IPv6)", "Local Network (IPv6)", true);
            }

            if (address.IsIPv6Multicast)
            {
                return new IpIntelligenceInfo(ipText, "LAN", "IPv6 Multicast", "Multicast", "LAN Discovery (IPv6)", "LAN Multicast", true);
            }

            byte[] b = address.GetAddressBytes();
            // fc00::/7 Unique Local Address (ULA)
            if ((b[0] & 0xFE) == 0xFC)
            {
                return new IpIntelligenceInfo(ipText, "LAN", "Private IPv6", "ULA", "Home / Private LAN (IPv6)", "Local Network (LAN)", true);
            }
        }

        foreach (var prefix in KnownPrefixes)
        {
            if (prefix.Network.Contains(address))
            {
                return new IpIntelligenceInfo(
                    ipText,
                    prefix.CountryCode,
                    prefix.CountryName,
                    prefix.Asn,
                    prefix.Organization,
                    prefix.Category,
                    false);
            }
        }

        return new IpIntelligenceInfo(ipText, "", "Public Internet", "", "Public Internet Host", "Public Internet", false);
    }

    private static List<KnownPrefix> BuildKnownPrefixes()
    {
        var list = new List<KnownPrefix>();
        void Add(string cidr, string cc, string country, string asn, string org, string cat)
        {
            if (IPNetwork.TryParse(cidr, out var net))
                list.Add(new KnownPrefix(net, cc, country, asn, org, cat));
        }

        // Cloudflare DNS & Edge CDN
        Add("1.1.1.0/24", "US", "United States", "AS13335", "Cloudflare DNS", "DNS / Edge CDN");
        Add("1.0.0.0/24", "US", "United States", "AS13335", "Cloudflare DNS", "DNS / Edge CDN");
        Add("104.16.0.0/12", "US", "United States", "AS13335", "Cloudflare, Inc.", "Global CDN / Security");
        Add("172.64.0.0/13", "US", "United States", "AS13335", "Cloudflare, Inc.", "Global CDN / Security");
        Add("162.158.0.0/15", "US", "United States", "AS13335", "Cloudflare, Inc.", "Global CDN / Security");
        Add("188.114.96.0/20", "US", "United States", "AS13335", "Cloudflare, Inc.", "Global CDN / Security");
        Add("2606:4700::/32", "US", "United States", "AS13335", "Cloudflare, Inc.", "Global CDN / Security");

        // Quad9 DNS
        Add("9.9.9.0/24", "CH", "Switzerland", "AS19281", "Quad9 Security DNS", "Security DNS Resolver");
        Add("149.112.112.0/24", "CH", "Switzerland", "AS19281", "Quad9 Security DNS", "Security DNS Resolver");
        Add("2620:fe::/48", "CH", "Switzerland", "AS19281", "Quad9 Security DNS", "Security DNS Resolver");

        // Google DNS & Cloud / YouTube
        Add("8.8.8.0/24", "US", "United States", "AS15169", "Google Public DNS", "DNS Resolver");
        Add("8.8.4.0/24", "US", "United States", "AS15169", "Google Public DNS", "DNS Resolver");
        Add("142.250.0.0/15", "US", "United States", "AS15169", "Google LLC", "Web / Media Infrastructure");
        Add("172.217.0.0/16", "US", "United States", "AS15169", "Google LLC", "Web / Media Infrastructure");
        Add("216.58.192.0/19", "US", "United States", "AS15169", "Google LLC", "Web / Media Infrastructure");
        Add("74.125.0.0/16", "US", "United States", "AS15169", "Google LLC", "Web / Media Infrastructure");
        Add("34.0.0.0/9", "US", "United States", "AS15169", "Google Cloud", "Cloud Infrastructure");
        Add("35.184.0.0/13", "US", "United States", "AS15169", "Google Cloud", "Cloud Infrastructure");
        Add("2001:4860::/32", "US", "United States", "AS15169", "Google LLC", "Web / Media Infrastructure");

        // Microsoft / Azure / Windows Update
        Add("20.0.0.0/8", "US", "United States", "AS8075", "Microsoft Azure", "Cloud / OS Services");
        Add("13.64.0.0/11", "US", "United States", "AS8075", "Microsoft Corporation", "Cloud / OS Services");
        Add("13.96.0.0/13", "US", "United States", "AS8075", "Microsoft Corporation", "Cloud / OS Services");
        Add("13.104.0.0/14", "US", "United States", "AS8075", "Microsoft Corporation", "Cloud / OS Services");
        Add("40.64.0.0/10", "US", "United States", "AS8075", "Microsoft Corporation", "Cloud / OS Services");
        Add("51.104.0.0/13", "EU", "Europe", "AS8075", "Microsoft Azure Europe", "Cloud / OS Services");
        Add("52.96.0.0/12", "US", "United States", "AS8075", "Microsoft 365", "Cloud / OS Services");
        Add("2603:1000::/24", "US", "United States", "AS8075", "Microsoft Corporation", "Cloud / OS Services");

        // GitHub
        Add("140.82.112.0/20", "US", "United States", "AS36459", "GitHub, Inc.", "Developer Platform");
        Add("185.199.108.0/22", "US", "United States", "AS54113", "GitHub Pages / Fastly", "CDN / Developer Platform");

        // Fastly CDN
        Add("151.101.0.0/16", "US", "United States", "AS54113", "Fastly CDN", "Global CDN");
        Add("199.232.0.0/16", "US", "United States", "AS54113", "Fastly CDN", "Global CDN");

        // Amazon AWS / CloudFront
        Add("3.0.0.0/9", "US", "United States", "AS16509", "Amazon AWS", "Cloud / CDN");
        Add("18.128.0.0/9", "US", "United States", "AS16509", "Amazon AWS", "Cloud / CDN");
        Add("52.0.0.0/10", "US", "United States", "AS16509", "Amazon AWS", "Cloud / CDN");
        Add("54.64.0.0/11", "US", "United States", "AS16509", "Amazon AWS", "Cloud / CDN");
        Add("13.32.0.0/15", "US", "United States", "AS16509", "Amazon CloudFront", "Global CDN");
        Add("13.224.0.0/14", "US", "United States", "AS16509", "Amazon CloudFront", "Global CDN");
        Add("99.84.0.0/16", "US", "United States", "AS16509", "Amazon CloudFront", "Global CDN");

        // Akamai CDN
        Add("23.0.0.0/12", "US", "United States", "AS20940", "Akamai Technologies", "Global CDN");
        Add("104.64.0.0/10", "US", "United States", "AS20940", "Akamai Technologies", "Global CDN");

        // Valve / Steam Gaming Network
        Add("155.133.224.0/19", "EU", "Europe / US", "AS32590", "Valve Corporation (Steam)", "Gaming Infrastructure");
        Add("162.254.192.0/21", "US", "United States", "AS32590", "Valve Corporation (Steam)", "Gaming Infrastructure");
        Add("185.25.180.0/22", "EU", "Europe", "AS32590", "Valve Corporation (Steam)", "Gaming Infrastructure");

        // Meta / Facebook / WhatsApp
        Add("157.240.0.0/16", "US", "United States", "AS32934", "Meta Platforms, Inc.", "Social Media");
        Add("31.13.64.0/18", "IE", "Ireland", "AS32934", "Meta Platforms, Inc.", "Social Media");

        // Apple Inc.
        Add("17.0.0.0/8", "US", "United States", "AS714", "Apple Inc.", "OS / Cloud Services");

        return list;
    }
}
