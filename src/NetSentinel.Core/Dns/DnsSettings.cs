using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSentinel.Sinkhole;

public enum BlockMode
{
    /// <summary>Answer blocked names with 0.0.0.0 / :: (programs fail immediately, no waiting).</summary>
    NullAddress = 0,
    /// <summary>Answer blocked names with "does not exist" (NXDOMAIN).</summary>
    NxDomain = 1,
}

public sealed record BlocklistSource(string Name, string Url, bool Enabled = true);

public sealed class DnsSettings
{
    /// <summary>Start the DNS server automatically when NetSentinel starts.</summary>
    public bool AutoStart { get; set; }

    /// <summary>127.0.0.1 = only this PC. 0.0.0.0 = every address of this PC, so other devices on your network can use it too.</summary>
    public string ListenAddress { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 53;

    public List<string> Upstreams { get; set; } = new() { "9.9.9.9", "1.1.1.1" };
    public BlockMode BlockMode { get; set; } = BlockMode.NullAddress;

    /// <summary>Also block a name when it is only an alias (CNAME) for a blocked name, e.g. a tracker hiding behind a harmless-looking name.</summary>
    public bool InspectCnames { get; set; } = true;

    /// <summary>Answer Firefox's "use-application-dns.net" check with "does not exist", which tells Firefox not to bypass this DNS server with its own DNS-over-HTTPS.</summary>
    public bool BlockBrowserDoh { get; set; } = true;

    public int CacheEntries { get; set; } = 10000;

    public List<BlocklistSource> Lists { get; set; } = new()
    {
        new("StevenBlack unified hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
    };

    /// <summary>Only allow queries from loopback and private/local network ranges, preventing open resolver abuse when listening on 0.0.0.0.</summary>
    public bool RestrictClientsToLocalNetwork { get; set; } = true;

    /// <summary>Additional CIDR ranges permitted to query this server (e.g. "10.200.0.0/16").</summary>
    public List<string> AllowedClientRanges { get; set; } = new();

    /// <summary>Maximum queries per second allowed per client IP (0 = unlimited). Protects against DNS amplification floods.</summary>
    public int RateLimitPerSecond { get; set; } = 50;

    /// <summary>One rule per entry: "example.com" (also blocks subdomains), "*.example.com", or a regular expression between slashes: /^ad[0-9]+\./</summary>
    public List<string> CustomBlock { get; set; } = new();
    public List<string> CustomAllow { get; set; } = new();

    /// <summary>How many days of persistent SQLite DNS query logs to keep (0 = do not prune).</summary>
    public int QueryHistoryRetentionDays { get; set; } = 30;

    /// <summary>Privacy: Mask the last octet of client IPv4 addresses and /64 of IPv6 addresses in query logs.</summary>
    public bool AnonymizeClientIps { get; set; }

    /// <summary>Privacy: Do not store domain names in persistent query logs (saved as [redacted]).</summary>
    public bool DoNotStoreDomains { get; set; }

    /// <summary>Custom authoritative local records (A, AAAA, CNAME, PTR, TXT) served directly by NetSentinel.</summary>
    public List<LocalDnsRecord> LocalRecords { get; set; } = new();

    /// <summary>Conditional forwarding rules for specific domains (e.g. *.home, *.lan, 168.192.in-addr.arpa) to a local router.</summary>
    public List<ConditionalForwardingRule> ConditionalForwarding { get; set; } = new();

    /// <summary>Client groups allowing per-client/device custom blocklists, rules, and blocking toggles.</summary>
    public List<ClientGroup> ClientGroups { get; set; } = new();

    public bool Validate(out string error)
    {
        error = "";
        if (!IPAddress.TryParse(ListenAddress, out _)) { error = $"'{ListenAddress}' is not a valid IP address to listen on."; return false; }
        if (Port is < 1 or > 65535) { error = "The port must be between 1 and 65535."; return false; }
        if (RateLimitPerSecond < 0) { error = "Rate limit cannot be negative."; return false; }
        if (QueryHistoryRetentionDays < 0) { error = "History retention days cannot be negative."; return false; }
        if (Upstreams.Count == 0) { error = "Add at least one upstream DNS server."; return false; }

        foreach (var u in Upstreams)
            if (!UpstreamEndpoint.TryParse(u, out _) && !TryParseUpstream(u, out _))
            {
                error = $"'{u}' is not a valid upstream server (use an IP address, https:// DoH URL, or tls:// DoT endpoint).";
                return false;
            }

        foreach (var range in AllowedClientRanges)
            if (!IPNetwork.TryParse(range.Trim(), out _)) { error = $"'{range}' is not a valid CIDR network (e.g. 192.168.1.0/24)."; return false; }

        foreach (var local in LocalRecords)
        {
            if (string.IsNullOrWhiteSpace(local.Domain)) { error = "Local record domain cannot be empty."; return false; }
            string rt = local.RecordType.Trim().ToUpperInvariant();
            if (rt is not ("A" or "AAAA" or "CNAME" or "PTR" or "TXT")) { error = $"Unsupported local record type '{local.RecordType}'. Supported types: A, AAAA, CNAME, PTR, TXT."; return false; }
            if (string.IsNullOrWhiteSpace(local.Value)) { error = $"Local record '{local.Domain}' has an empty value."; return false; }
        }

        foreach (var fwd in ConditionalForwarding)
        {
            if (string.IsNullOrWhiteSpace(fwd.DomainSuffix)) { error = "Conditional forwarding domain suffix cannot be empty."; return false; }
            if (!UpstreamEndpoint.TryParse(fwd.TargetServer, out _) && !TryParseUpstream(fwd.TargetServer, out _))
            {
                error = $"'{fwd.TargetServer}' is not a valid forwarding target server for '{fwd.DomainSuffix}'.";
                return false;
            }
        }

        return true;
    }

    public IReadOnlyList<UpstreamEndpoint> ParsedUpstreams() =>
        Upstreams.Select(u => UpstreamEndpoint.TryParse(u, out var ep) ? ep : null)
                 .Where(ep => ep is not null)
                 .Select(ep => ep!)
                 .ToList();

    public IReadOnlyList<IPEndPoint> UpstreamEndpoints() =>
        Upstreams.Select(u => TryParseUpstream(u, out var ep) ? ep : null).Where(ep => ep is not null).Select(ep => ep!).ToList();

    public static bool TryParseUpstream(string text, out IPEndPoint endpoint)
    {
        endpoint = new IPEndPoint(IPAddress.Any, 53);
        text = text.Trim();
        if (text.Length == 0) return false;

        // Forms: "9.9.9.9", "9.9.9.9:5353", "2620:fe::fe", "[2620:fe::fe]:5353".
        // Careful: IPAddress.TryParse accepts "[2620:fe::fe]:5353" but silently throws the port away, so look for a port first.
        bool hasPort = text.StartsWith('[') || text.Count(c => c == ':') == 1;
        if (hasPort)
        {
            if (IPEndPoint.TryParse(text, out var withPort) && withPort.Port is > 0 and <= 65535)
            {
                endpoint = withPort;
                return true;
            }
            return false;
        }

        if (IPAddress.TryParse(text, out var plain))
        {
            endpoint = new IPEndPoint(plain, 53);
            return true;
        }
        return false;
    }
}

public sealed class DnsSettingsStore
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _file;

    public DnsSettingsStore(string file) => _file = file;

    public static string DefaultPath => NetSentinel.Core.EngineStoragePaths.DnsSettingsPath;

    public DnsSettings Load()
    {
        try
        {
            if (!File.Exists(_file)) return new DnsSettings();
            return JsonSerializer.Deserialize<DnsSettings>(File.ReadAllText(_file), Json) ?? new DnsSettings();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            try { File.Move(_file, _file + ".bad", overwrite: true); } catch (Exception) { /* nothing more to do */ }
            return new DnsSettings();
        }
    }

    public void Save(DnsSettings settings)
    {
        var dir = Path.GetDirectoryName(_file);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        string temp = _file + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(settings, Json));
        File.Move(temp, _file, overwrite: true);
    }
}
