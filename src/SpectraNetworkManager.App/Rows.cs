using System.ComponentModel;
using System.Net;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Ui;

/// <summary>One line in the connections grid. State, host name and signature result can change while the connection lives.</summary>
public sealed class ConnectionRow : INotifyPropertyChanged
{
    private ConnectionState _state;
    private string _host = "";
    private string _signer;

    public ConnectionRow(ConnectionView view)
    {
        var c = view.Connection;
        Protocol = c.Protocol.ToString().ToUpperInvariant();
        Local = Display.Endpoint(c.Local);
        RemoteAddress = c.Protocol == SpectraNetworkManager.Core.Protocol.Udp ? null : c.Remote?.Address;
        Remote = c.Protocol == SpectraNetworkManager.Core.Protocol.Udp ? "*" : Display.Endpoint(c.Remote);
        Pid = c.ProcessId;
        Program = view.Process.Name;
        Path = view.Process.Path ?? "";
        _signer = Path.Length > 0 ? "checking..." : "";
        _state = c.State;
    }

    public string Protocol { get; }
    public string Local { get; }
    public string Remote { get; }
    public IPAddress? RemoteAddress { get; }
    public int Pid { get; }
    public string Program { get; }
    public string Path { get; }

    public string Signer
    {
        get => _signer;
        private set
        {
            if (_signer == value) return;
            _signer = value;
            Raise(nameof(Signer));
        }
    }

    public void SetSignature(SignatureInfo? signature) =>
        Signer = signature?.Describe() ?? (Path.Length > 0 ? "checking..." : "");

    public string Host
    {
        get => _host;
        set
        {
            value ??= "";
            if (_host == value) return;
            _host = value;
            Raise(nameof(Host));
        }
    }

    public ConnectionState StateValue
    {
        get => _state;
        set
        {
            if (_state == value) return;
            _state = value;
            Raise(nameof(StateValue));
            Raise(nameof(State));
        }
    }

    public string State => Display.State(_state);

    private long _bytesInSec;
    private long _bytesOutSec;
    public string SpeedIn => Display.Rate(_bytesInSec);
    public string SpeedOut => Display.Rate(_bytesOutSec);

    public void UpdateSpeed(long inSec, long outSec)
    {
        if (_bytesInSec == inSec && _bytesOutSec == outSec) return;
        _bytesInSec = inSec;
        _bytesOutSec = outSec;
        Raise(nameof(SpeedIn));
        Raise(nameof(SpeedOut));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Raise(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>One line in the "Programs" grid.</summary>
public sealed class ProgramRow : INotifyPropertyChanged
{
    private ProgramSummary _s;
    private ProgramStanding _standing;

    public ProgramRow(ProgramSummary s, ProgramStanding standing)
    {
        _s = s;
        _standing = standing;
    }

    public string Key => _s.Key;
    public string Name => _s.Name;
    public string Path => _s.Path ?? "";
    public int Processes => _s.Processes;
    public int Established => _s.Established;
    public int Listening => _s.Listening;
    public int UdpEndpoints => _s.UdpEndpoints;
    public int InternetPeers => _s.InternetPeers;

    public ProgramRule? Rule => _standing.Rule;
    public SignatureInfo? Signature => _standing.Signature;
    public string Publisher => _standing.Signature?.Publisher ?? "";
    public bool IsTrusted => _standing.IsTrusted;
    public string Signer => _standing.Signature?.Describe() ?? (Path.Length > 0 ? "checking..." : "");

    /// <summary>A verified publisher that could be added to the trust list (and is not there yet).</summary>
    public bool CanTrustPublisher => _standing.Signature is { Status: SignatureStatus.Valid, Publisher: not null } && !_standing.PublisherTrusted;

    /// <summary>Internet activity but nobody has decided yet: this is what Learning mode highlights.</summary>
    public bool IsNew => !_standing.IsDecided && _s.InternetPeers > 0 && _s.Path is not null;

    public string Verdict
    {
        get
        {
            if (_standing.Rule is { } rule)
                return rule.Action == RuleAction.Block ? "BLOCKED" : "Allowed";
            if (_standing.Signature is { IsAlarming: true } bad)
                return bad.Status == SignatureStatus.Tampered ? "WARNING: signature broken" : "WARNING: untrusted signature";
            if (_standing.IsTrusted)
                return "Trusted: " + _standing.Signature!.Publisher;
            if (_s.Path is null)
                return "unknown (needs Administrator)";
            return _s.InternetPeers > 0 ? "NEW - no rule yet" : "-";
        }
    }

    public void Update(ProgramSummary s, ProgramStanding standing)
    {
        if (_s == s && _standing == standing) return;
        _s = s;
        _standing = standing;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty)); // refresh every property
    }

    private long _bytesInSec;
    private long _bytesOutSec;
    public string SpeedIn => Display.Rate(_bytesInSec);
    public string SpeedOut => Display.Rate(_bytesOutSec);

    public void UpdateSpeed(long inSec, long outSec)
    {
        if (_bytesInSec == inSec && _bytesOutSec == outSec) return;
        _bytesInSec = inSec;
        _bytesOutSec = outSec;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SpeedIn)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SpeedOut)));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>One line in the live event list on the right.</summary>
public sealed record EventLine(string Text, bool Opened, bool Alert = false);

/// <summary>One line in the "Firewall blocks" grid.</summary>
public sealed record BlockRow(string Time, string Direction, string Protocol, string Source, string Destination, int Pid, string Application)
{
    public static BlockRow From(BlockEvent e) => new(
        e.Time.ToString("HH:mm:ss"),
        e.Inbound ? "IN" : "OUT",
        e.ProtocolName,
        $"{e.SourceAddress}:{e.SourcePort}",
        $"{e.DestinationAddress}:{e.DestinationPort}",
        e.ProcessId,
        string.IsNullOrEmpty(e.Application) ? "(unknown)" : e.Application);
}

/// <summary>One line in the "Rules" grid: a stored decision plus whether Windows Firewall really has the matching rules.</summary>
public sealed record RuleRow(string Name, string Decision, string Direction, string Scope, string Firewall, string Since, string Path, ProgramRule Rule)
{
    public static RuleRow From(ProgramRule rule, string firewallStatus) => new(
        System.IO.Path.GetFileName(rule.Path),
        rule.Action == RuleAction.Block ? "BLOCKED" : "Allowed",
        rule.Action == RuleAction.Block ? ProgramRule.DescribeDirection(rule.Direction) : "-",
        rule.Action == RuleAction.Block ? rule.EffectiveScope.Describe() : "-",
        firewallStatus,
        rule.Created.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
        rule.Path,
        rule);
}

/// <summary>One line in the "Trusted publishers" grid.</summary>
public sealed record PublisherRow(string Name);

/// <summary>One line in the DNS query log.</summary>
public sealed record DnsRow(string Time, string Client, string Domain, string Type, string Result, string Detail, int Ms, bool IsBlocked, bool IsFailed, DnsLogEntry Entry)
{
    public string ClientDisplay => (Client == "127.0.0.1" || Client == "::1" || Client == "localhost")
        ? $"{Client} (This PC)"
        : Client;

    public static DnsRow From(DnsLogEntry e) => new(
        e.Time.ToString("HH:mm:ss"),
        e.Client,
        e.Domain,
        e.Type,
        e.Outcome switch
        {
            DnsOutcome.Blocked => "BLOCKED",
            DnsOutcome.Cached => "cached",
            DnsOutcome.Forwarded => "ok",
            DnsOutcome.Failed => "FAILED",
            _ => "refused",
        },
        e.Detail ?? "",
        e.Milliseconds,
        e.Outcome == DnsOutcome.Blocked,
        e.Outcome == DnsOutcome.Failed,
        e);

    public string TypeToolTip => (Type?.ToUpperInvariant() ?? "") switch
    {
        "A" => "A (IPv4 Address Record)\nTranslates a domain name into an IPv4 address (e.g. 192.0.2.1) for web and network connections.",
        "AAAA" => "AAAA (IPv6 Address Record)\nTranslates a domain name into a 128-bit IPv6 address (e.g. 2001:db8::1).",
        "PTR" => "PTR (Pointer / Reverse DNS)\nTranslates an IP address back into a hostname (reverse lookup, e.g. .ip6.arpa or .in-addr.arpa).",
        "HTTPS" => "HTTPS (Service Binding / RFC 9460)\nModern DNS record used by browsers to discover HTTP/3, TLS configurations, and encrypted parameters directly before connecting.",
        "CNAME" => "CNAME (Canonical Name)\nAn alias that maps a domain name to another canonical domain name.",
        "MX" => "MX (Mail Exchange)\nDirects email traffic to the domain's mail servers.",
        "TXT" => "TXT (Text Record)\nCarries human or machine-readable text, commonly used for SPF, DKIM, and domain ownership verification.",
        "SRV" => "SRV (Service Record)\nSpecifies the location (hostname and port) of servers for specified services (LDAP, SIP, gaming, VoIP).",
        "SOA" => "SOA (Start of Authority)\nSupplies administrative information about a DNS zone (primary nameserver, admin contact, serial number).",
        "NS" => "NS (Name Server)\nDelegates a DNS zone to an authoritative name server.",
        _ => $"DNS Query Type: {Type}"
    };

    public string TypeDescription => (Type?.ToUpperInvariant() ?? "") switch
    {
        "A" => "(IPv4 Address Lookup)",
        "AAAA" => "(IPv6 Address Lookup)",
        "PTR" => "(Reverse IP-to-Name Lookup)",
        "HTTPS" => "(Encrypted Web Service Binding)",
        "CNAME" => "(Domain Alias Redirect)",
        "MX" => "(Mail Server Exchange)",
        "TXT" => "(Domain Verification / SPF)",
        "SRV" => "(Service Locator)",
        "SOA" => "(Zone Authority)",
        "NS" => "(Authoritative Name Server)",
        _ => "(DNS Query)"
    };
}
