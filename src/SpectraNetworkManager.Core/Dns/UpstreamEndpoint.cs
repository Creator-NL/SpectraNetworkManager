using System.Net;

namespace SpectraNetworkManager.Sinkhole;

public enum UpstreamKind
{
    Standard = 0, // Plain UDP/TCP DNS on port 53
    DoH = 1,      // DNS-over-HTTPS (RFC 8484)
    DoT = 2       // DNS-over-TLS (RFC 7858)
}

public sealed record UpstreamStatus(
    string EndpointText,
    string DisplayName,
    UpstreamKind Kind,
    bool IsHealthy,
    int LastLatencyMs,
    DateTimeOffset LastChecked,
    string? LastError
);

/// <summary>
/// Represents and parses configured upstream DNS endpoints:
/// Plain IP/Port (e.g. "9.9.9.9", "1.1.1.1:5353"),
/// DoH (e.g. "https://9.9.9.9/dns-query", "https://1.1.1.1/dns-query"),
/// and DoT (e.g. "tls://9.9.9.9:853", "dot://1.1.1.1:853").
/// </summary>
public sealed class UpstreamEndpoint
{
    public UpstreamKind Kind { get; }
    public string OriginalText { get; }
    public string DisplayName { get; }
    public IPEndPoint? StandardEndpoint { get; }
    public Uri? DohUri { get; }
    public string? DotHost { get; }
    public int DotPort { get; }

    private UpstreamEndpoint(
        UpstreamKind kind,
        string originalText,
        string displayName,
        IPEndPoint? standardEndpoint = null,
        Uri? dohUri = null,
        string? dotHost = null,
        int dotPort = 853)
    {
        Kind = kind;
        OriginalText = originalText;
        DisplayName = displayName;
        StandardEndpoint = standardEndpoint;
        DohUri = dohUri;
        DotHost = dotHost;
        DotPort = dotPort;
    }

    public static bool TryParse(string text, out UpstreamEndpoint endpoint)
    {
        endpoint = null!;
        text = text?.Trim() ?? "";
        if (text.Length == 0) return false;

        // 1. DoH: starts with https://
        if (text.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (Uri.TryCreate(text, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps)
            {
                string display = $"DoH: {uri.Host}{uri.PathAndQuery}";
                endpoint = new UpstreamEndpoint(UpstreamKind.DoH, text, display, dohUri: uri);
                return true;
            }
            return false;
        }

        // 2. DoT: starts with tls:// or dot://
        if (text.StartsWith("tls://", StringComparison.OrdinalIgnoreCase) || text.StartsWith("dot://", StringComparison.OrdinalIgnoreCase))
        {
            int prefixLen = text.StartsWith("tls://", StringComparison.OrdinalIgnoreCase) ? 6 : 6;
            string target = text[prefixLen..].Trim();
            if (target.Length == 0) return false;

            string host = target;
            int port = 853;

            if (target.StartsWith('[') && target.Contains(']'))
            {
                int closeBracket = target.IndexOf(']');
                host = target[1..closeBracket];
                if (target.Length > closeBracket + 1 && target[closeBracket + 1] == ':')
                {
                    if (!int.TryParse(target[(closeBracket + 2)..], out port) || port is < 1 or > 65535) return false;
                }
            }
            else if (target.Contains(':') && target.IndexOf(':') == target.LastIndexOf(':'))
            {
                var parts = target.Split(':');
                host = parts[0];
                if (!int.TryParse(parts[1], out port) || port is < 1 or > 65535) return false;
            }

            string display = $"DoT: {host}:{port}";
            endpoint = new UpstreamEndpoint(UpstreamKind.DoT, text, display, dotHost: host, dotPort: port);
            return true;
        }

        // 3. Plain IP endpoint (UDP/TCP)
        if (DnsSettings.TryParseUpstream(text, out var ipEp))
        {
            if (ipEp.Port == 853)
            {
                // Explicit port 853 implies DoT
                string dotDisplay = $"DoT: {ipEp.Address}:853";
                endpoint = new UpstreamEndpoint(UpstreamKind.DoT, text, dotDisplay, dotHost: ipEp.Address.ToString(), dotPort: 853);
                return true;
            }

            string stdDisplay = ipEp.Port == 53 ? ipEp.Address.ToString() : $"{ipEp.Address}:{ipEp.Port}";
            endpoint = new UpstreamEndpoint(UpstreamKind.Standard, text, stdDisplay, standardEndpoint: ipEp);
            return true;
        }

        return false;
    }

    public IUpstreamResolver CreateResolver(TimeSpan? timeout = null, HttpMessageHandler? httpHandler = null)
    {
        return Kind switch
        {
            UpstreamKind.DoH => new DohUpstreamResolver(DohUri!, timeout, httpHandler),
            UpstreamKind.DoT => new DotUpstreamResolver(DotHost!, DotPort, timeout),
            _ => new NetworkUpstreamResolver(new[] { StandardEndpoint! }, timeout)
        };
    }
}
