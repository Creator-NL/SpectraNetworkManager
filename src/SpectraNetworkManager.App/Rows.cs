using System.ComponentModel;
using System.Net;
using System.Runtime.CompilerServices;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Platform.Windows;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Ui;

/// <summary>One line in the connections grid. State, host name and signature result can change while the connection lives.</summary>
public sealed class ConnectionRow : INotifyPropertyChanged
{
    private ConnectionState _state;
    private string _host = "";
    private string _signer;
    private SignatureInfo? _signature;
    private int? _parentPid;
    private string _parentName = "";
    private string _commandLine = "";
    private string _serviceNames = "";
    private DateTimeOffset? _startTimeUtc;
    private string _remoteIntel = "";

    public ConnectionRow(ConnectionView view, IpIntelligenceInfo? remoteIntel = null)
    {
        var c = view.Connection;
        Protocol = c.Protocol.ToString().ToUpperInvariant();
        Local = Display.Endpoint(c.Local);
        RemoteAddress = c.Protocol == SpectraNetworkManager.Core.Protocol.Udp ? null : c.Remote?.Address;
        RemotePort = c.Protocol == SpectraNetworkManager.Core.Protocol.Udp ? 0 : (c.Remote?.Port ?? 0);
        Remote = c.Protocol == SpectraNetworkManager.Core.Protocol.Udp ? "*" : Display.Endpoint(c.Remote);
        Pid = c.ProcessId;
        Program = view.Process.Name;
        Path = view.Process.Path ?? "";
        _parentPid = view.Process.ParentPid;
        _parentName = view.Process.ParentName ?? "";
        _commandLine = view.Process.CommandLine ?? "";
        _serviceNames = view.Process.ServiceNames ?? "";
        _startTimeUtc = view.Process.StartTimeUtc;
        _remoteIntel = remoteIntel?.ShortDisplay ?? "";
        RemoteIntelInfo = remoteIntel;
        _signer = Path.Length > 0 ? "checking..." : "";
        _state = c.State;
    }

    public string Protocol { get; }
    public string Local { get; }
    public string Remote { get; }
    public IPAddress? RemoteAddress { get; }
    public int RemotePort { get; }
    public int Pid { get; }
    public string Program { get; }
    public string Path { get; }

    public int? ParentPid => _parentPid;
    public string ParentName => _parentName;
    public string CommandLine => _commandLine;
    public string ServiceNames => _serviceNames;
    public DateTimeOffset? StartTimeUtc => _startTimeUtc;
    public SignatureInfo? Signature => _signature;
    public IpIntelligenceInfo? RemoteIntelInfo { get; private set; }

    public string ServiceOrParent =>
        !string.IsNullOrEmpty(_serviceNames)
            ? $"⚙ {_serviceNames}"
            : (!string.IsNullOrEmpty(_parentName)
                ? $"↖ {_parentName}{(_parentPid.HasValue ? $" ({_parentPid.Value})" : "")}"
                : "");

    public string RemoteIntel
    {
        get => _remoteIntel;
        set
        {
            value ??= "";
            if (_remoteIntel == value) return;
            _remoteIntel = value;
            Raise(nameof(RemoteIntel));
        }
    }

    public void SetRemoteIntel(IpIntelligenceInfo? info)
    {
        RemoteIntelInfo = info;
        RemoteIntel = info?.ShortDisplay ?? "";
    }

    public void UpdateProcessInfo(ProcessInfo proc)
    {
        bool changed = false;
        if (_parentPid != proc.ParentPid) { _parentPid = proc.ParentPid; changed = true; }
        if (_parentName != (proc.ParentName ?? "")) { _parentName = proc.ParentName ?? ""; changed = true; }
        if (_commandLine != (proc.CommandLine ?? "")) { _commandLine = proc.CommandLine ?? ""; changed = true; }
        if (_serviceNames != (proc.ServiceNames ?? "")) { _serviceNames = proc.ServiceNames ?? ""; changed = true; }
        if (_startTimeUtc != proc.StartTimeUtc) { _startTimeUtc = proc.StartTimeUtc; changed = true; }
        if (changed)
        {
            Raise(nameof(ParentPid));
            Raise(nameof(ParentName));
            Raise(nameof(CommandLine));
            Raise(nameof(ServiceNames));
            Raise(nameof(StartTimeUtc));
            Raise(nameof(ServiceOrParent));
        }
    }

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

    public void SetSignature(SignatureInfo? signature)
    {
        _signature = signature;
        Signer = signature?.Describe() ?? (Path.Length > 0 ? "checking..." : "");
        Raise(nameof(Signature));
    }

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

/// <summary>One line in the "Firewall blocks" grid, with enriched caller identity, service name, and root-cause diagnostic.</summary>
public sealed record BlockRow(
    string Time,
    string Direction,
    string Protocol,
    string Source,
    string Destination,
    int Pid,
    string Application,
    string CallerDisplayName,
    string Service,
    string Category,
    string DestinationDisplay,
    string DiagnosticExplanation,
    bool IsNoise,
    bool IsSelf,
    string SourceAddress,
    int SourcePort,
    string DestinationAddress,
    int DestinationPort,
    BlockEvent RawEvent)
{
    public static BlockRow From(BlockEvent e)
    {
        int targetPort = e.Inbound ? e.SourcePort : e.DestinationPort;
        string proto = e.ProtocolName;

        // 1. Resolve human-readable service name
        string service = targetPort switch
        {
            137 => "NetBIOS-NS",
            138 => "NetBIOS-Dgm",
            139 => "NetBIOS-SSN",
            5355 => "LLMNR",
            5353 => "mDNS",
            1900 => "SSDP / UPnP",
            53 => "DNS",
            80 => "HTTP",
            443 => (e.DestinationAddress.StartsWith("162.159.", StringComparison.OrdinalIgnoreCase) || e.DestinationAddress.StartsWith("1.1.1.", StringComparison.OrdinalIgnoreCase) || e.DestinationAddress.StartsWith("9.9.9.", StringComparison.OrdinalIgnoreCase) || e.DestinationAddress.StartsWith("8.8.8.", StringComparison.OrdinalIgnoreCase))
                ? "HTTPS (DoH)"
                : "HTTPS",
            445 => "SMB / Direct-Host",
            135 => "MS-RPC",
            123 => "NTP",
            67 or 68 => "DHCP",
            0 when proto.Contains("ICMP", StringComparison.OrdinalIgnoreCase) => "ICMP Ping",
            _ => WellKnownPorts.GetServiceName(targetPort, e.ProtocolNumber == 17 ? SpectraNetworkManager.Core.Protocol.Udp : SpectraNetworkManager.Core.Protocol.Tcp)
        };

        // 2. Identify caller / process attribution
        string app = string.IsNullOrWhiteSpace(e.Application) ? "" : e.Application;
        string callerName;

        if (string.IsNullOrEmpty(app))
        {
            callerName = targetPort switch
            {
                137 or 138 or 139 => "Windows Kernel (NetBIOS)",
                5355 => "Windows Kernel (LLMNR)",
                1900 or 5353 => "Windows Kernel (SSDP / mDNS)",
                67 or 68 => "Windows Kernel (DHCP)",
                _ when proto.Contains("ICMP", StringComparison.OrdinalIgnoreCase) => "Windows Kernel (ICMP Ping)",
                _ => e.Inbound ? "External Remote Host" : "Windows Kernel / System"
            };
        }
        else if (app.Contains("spectranetworkmanager", StringComparison.OrdinalIgnoreCase))
        {
            if (targetPort == 443 || e.DestinationAddress.StartsWith("162.159.", StringComparison.OrdinalIgnoreCase) || e.DestinationAddress.StartsWith("1.1.1.", StringComparison.OrdinalIgnoreCase) || e.DestinationAddress.StartsWith("9.9.9.", StringComparison.OrdinalIgnoreCase))
            {
                callerName = "SpectraNetworkManager (Upstream DoH)";
            }
            else if (proto.Contains("ICMP", StringComparison.OrdinalIgnoreCase))
            {
                callerName = "SpectraNetworkManager (Gateway Ping)";
            }
            else
            {
                callerName = "SpectraNetworkManager";
            }
        }
        else
        {
            callerName = System.IO.Path.GetFileName(app);
            if (string.IsNullOrEmpty(callerName)) callerName = app;
        }

        // 3. Categorize event
        bool isNoise = targetPort is 137 or 138 or 139 or 1900 or 5353 or 5355
            || e.DestinationAddress == "239.255.255.250"
            || e.DestinationAddress.StartsWith("224.0.0.", StringComparison.OrdinalIgnoreCase)
            || e.DestinationAddress.EndsWith(".255", StringComparison.OrdinalIgnoreCase);

        bool isSelf = app.Contains("spectranetworkmanager", StringComparison.OrdinalIgnoreCase);

        string category;
        if (isNoise)
        {
            category = "Local Discovery Noise";
        }
        else if (isSelf)
        {
            category = "Spectra Self-Traffic";
        }
        else if (e.Inbound)
        {
            category = "Inbound Drop";
        }
        else
        {
            category = "Application Block";
        }

        // 4. Generate plain-English diagnostic explanation
        string explanation;
        if (isNoise)
        {
            explanation = $"Local subnet discovery: The Windows networking stack ({callerName}) broadcast a {service} probe to {e.DestinationAddress}:{e.DestinationPort}. This is routine Windows background activity for device and name discovery on your local network.";
        }
        else if (isSelf)
        {
            explanation = $"Spectra internal communication: Spectra forwarded an upstream DNS query via DoH or sent a gateway ping. The operation succeeded; this entry is a transient TCP reset/FIN or ICMP packet dropped by the kernel after socket closure.";
        }
        else if (e.Inbound)
        {
            explanation = $"Unsolicited inbound traffic: An external host at {e.SourceAddress}:{e.SourcePort} attempted to reach local port {e.DestinationPort} ({service}). It was dropped by Windows Firewall's default inbound security policy.";
        }
        else
        {
            explanation = $"Outbound connection dropped: Windows Filtering Platform blocked an outbound connection from '{callerName}' to {e.DestinationAddress}:{e.DestinationPort} ({service}). In Strict Mode, this program requires an explicit allow rule to access the internet.";
        }

        return new BlockRow(
            e.Time.ToLocalTime().ToString("HH:mm:ss"),
            e.Inbound ? "IN" : "OUT",
            proto,
            $"{e.SourceAddress}:{e.SourcePort}",
            $"{e.DestinationAddress}:{e.DestinationPort}",
            e.ProcessId,
            string.IsNullOrEmpty(app) ? "(unknown)" : app,
            callerName,
            service,
            category,
            $"{e.DestinationAddress}:{e.DestinationPort}",
            explanation,
            isNoise,
            isSelf,
            e.SourceAddress,
            e.SourcePort,
            e.DestinationAddress,
            e.DestinationPort,
            e);
    }
}

/// <summary>One line in the "Rules" grid: a stored decision plus whether Windows Firewall really has the matching rules.</summary>
public sealed record RuleRow(string Name, string Decision, string Direction, string Scope, string Firewall, string Since, string Path, ProgramRule Rule)
{
    public static RuleRow From(ProgramRule rule, string firewallStatus) => new(
        System.IO.Path.GetFileName(rule.Path),
        rule.Action == RuleAction.Block
            ? (rule.Note?.Contains("QUARANTINE", StringComparison.OrdinalIgnoreCase) == true ? "QUARANTINED" : "BLOCKED")
            : "Allowed",
        rule.Action == RuleAction.Block ? ProgramRule.DescribeDirection(rule.Direction) : "-",
        rule.Action == RuleAction.Block ? rule.EffectiveScope.Describe() : "-",
        firewallStatus,
        rule.Created.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
        rule.Path,
        rule);
}

/// <summary>One line in the "Trusted publishers" grid.</summary>
public sealed record PublisherRow(string Name);

/// <summary>One line in the "Startup" grid.</summary>
public sealed class StartupRow : INotifyPropertyChanged
{
    private StartupEntry _entry;
    private SignatureInfo? _signature;
    private string _firewallStatus;

    public StartupRow(StartupEntry entry, SignatureInfo? signature, string firewallStatus)
    {
        _entry = entry;
        _signature = signature;
        _firewallStatus = firewallStatus;
    }

    public StartupEntry Entry => _entry;
    public string Id => _entry.Id;
    public StartupSourceKind SourceKind => _entry.SourceKind;
    public bool IsEnabled => _entry.IsEnabled;
    public bool IsDisabled => !_entry.IsEnabled;
    public bool FileExists => !string.IsNullOrWhiteSpace(_entry.ExecutablePath) && System.IO.File.Exists(_entry.ExecutablePath);
    public string Status => _entry.IsEnabled ? "● ENABLED" : "○ DISABLED";
    public string Name => _entry.Name;
    public string ExecutablePath => _entry.ExecutablePath;
    public string Command => _entry.RawCommand;
    public string Location => _entry.LocationDisplay;

    public string Publisher
    {
        get
        {
            if (_signature != null)
            {
                if (_signature.Status == SignatureStatus.Valid)
                {
                    return _signature.Describe();
                }
                if (_signature.Status == SignatureStatus.NotSigned && !string.IsNullOrWhiteSpace(_entry.PublisherHint))
                {
                    return _entry.PublisherHint.StartsWith('✓')
                        ? _entry.PublisherHint
                        : $"{_entry.PublisherHint} (not signed)";
                }
                return _signature.Describe();
            }

            if (FileExists)
            {
                return !string.IsNullOrWhiteSpace(_entry.PublisherHint) ? _entry.PublisherHint : "checking...";
            }

            return "⚠️ (file not found — orphaned)";
        }
    }

    public bool IsUnsigned => _signature is { IsAlarming: true };

    public string FirewallStatus => _firewallStatus;

    public void Update(StartupEntry entry, SignatureInfo? signature, string firewallStatus)
    {
        _entry = entry;
        _signature = signature;
        _firewallStatus = firewallStatus;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>One line in the DNS query log. Uses reference equality so mutable properties never corrupt WPF DataGrid selection hashtables.</summary>
public sealed record DnsRow(string Time, string Client, string Domain, string Type, string Result, string Detail, int Ms, bool IsBlocked, bool IsFailed, DnsLogEntry Entry) : INotifyPropertyChanged
{
    private string _callerProgram = "";

    public string ClientDisplay => Client;

    public string CallerProgram
    {
        get => _callerProgram;
        set
        {
            if (_callerProgram != value)
            {
                _callerProgram = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CallerProgram)));
            }
        }
    }

    public bool Equals(DnsRow? other) => ReferenceEquals(this, other);
    public override int GetHashCode() => RuntimeHelpers.GetHashCode(this);

    public event PropertyChangedEventHandler? PropertyChanged;

    public static DnsRow From(DnsLogEntry e, string caller = "")
    {
        var row = new DnsRow(
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
        row._callerProgram = caller;
        return row;
    }

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

/// <summary>One line in the "Packets" inspector table.</summary>
public sealed class PacketRow
{
    public CapturedPacket Packet { get; }

    public long Id => Packet.Id;
    public string TimestampDisplay => Packet.Timestamp.ToLocalTime().ToString("HH:mm:ss.fff");
    public string DirectionDisplay => Packet.DirectionDisplay;
    public string ProtocolDisplay => Packet.ProtocolDisplay;
    public string? HostOrSni => Packet.HostOrSni;
    public string ProcessDisplay => Packet.ProcessDisplay;
    public string SourceEndpointDisplay => Packet.SourceEndpointDisplay;
    public string DestinationEndpointDisplay => Packet.DestinationEndpointDisplay;
    public int TotalLength => Packet.TotalLength;
    public string TcpFlags => Packet.TcpFlags;
    public string Info => Packet.Info;

    public PacketRow(CapturedPacket packet)
    {
        Packet = packet;
    }
}

/// <summary>One row in the TV & Mobile Protection Hub.</summary>
public sealed class TvMobileDeviceRow : INotifyPropertyChanged
{
    private DiscoveredDevice _device;
    private SpectraNetworkManager.Core.Devices.DeviceProtectionInfo _protection;
    private string _groupName = "Default";

    public DiscoveredDevice Device => _device;
    public string IpString => _device.IpString;
    public string Hostname => !string.IsNullOrEmpty(_device.Hostname) ? _device.Hostname : _device.IpString;
    public string MacAddress => _device.MacAddress;
    public string Vendor => !string.IsNullOrEmpty(_device.Vendor) ? _device.Vendor : "Unknown Vendor";
    public string DeviceTypeDisplay => _device.KindDisplay;
    public string ProtectionBadge => _protection.BadgeText;
    public string ProtectionColor => _protection.StatusColor;
    public string ProtectionDesc => _protection.Description;
    public string AssignedGroup { get => _groupName; set { _groupName = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(AssignedGroup))); } }
    public int TotalQueries => _protection.TotalQueries;
    public int BlockedQueries => _protection.BlockedQueries;
    public string LastQueryDisplay => _protection.LastQueryTimeUtc.HasValue ? _protection.LastQueryTimeUtc.Value.ToLocalTime().ToString("HH:mm:ss") : "(never)";

    public TvMobileDeviceRow(DiscoveredDevice device, SpectraNetworkManager.Core.Devices.DeviceProtectionInfo protection, string groupName = "Default")
    {
        _device = device;
        _protection = protection;
        _groupName = groupName;
    }

    public void Update(SpectraNetworkManager.Core.Devices.DeviceProtectionInfo protection, string groupName)
    {
        _protection = protection;
        _groupName = groupName;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }

    public void Refresh()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>One row in the Browser Guard rules table.</summary>
public sealed class BrowserGuardRuleRow : INotifyPropertyChanged
{
    private readonly Action<BrowserGuardRuleRow, bool>? _onToggled;
    public SpectraNetworkManager.Core.BrowserGuard.BrowserGuardRule Rule { get; }

    public string Id => Rule.Id;
    public string Title => Rule.Title;
    public string Pattern => Rule.Pattern;
    public string Description => Rule.Description;
    public string ResourceType => Rule.ResourceType;
    public string ActionDisplay => Rule.Action == SpectraNetworkManager.Core.BrowserGuard.GuardAction.Block ? "🚫 BLOCK" : "🛡️ ALLOW";
    public string ActionText => Rule.Action == SpectraNetworkManager.Core.BrowserGuard.GuardAction.Block ? "BLOCK" : "ALLOW";
    public string RuleTypeText => Rule.IsBuiltIn ? "BUILT-IN RULE" : "CUSTOM RULE";
    public string DnrFilter => SpectraNetworkManager.Core.BrowserGuard.BrowserGuardManager.ToDnrUrlFilter(Rule.Pattern);
    public bool IsBuiltIn => Rule.IsBuiltIn;

    public bool IsEnabled
    {
        get => Rule.Enabled;
        set
        {
            if (Rule.Enabled != value)
            {
                Rule.Enabled = value;
                _onToggled?.Invoke(this, value);
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsEnabled)));
            }
        }
    }

    public BrowserGuardRuleRow(SpectraNetworkManager.Core.BrowserGuard.BrowserGuardRule rule, Action<BrowserGuardRuleRow, bool>? onToggled = null)
    {
        Rule = rule;
        _onToggled = onToggled;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>One row in the Browser Guard pending element picker confirmation queue.</summary>
public sealed class ElementPickerBlockRequestRow
{
    public SpectraNetworkManager.Core.BrowserGuard.ElementPickerBlockRequest Request { get; }

    public string Id => Request.Id;
    public string Title => Request.Title;
    public string Url => Request.Url;
    public string Pattern => Request.Pattern;
    public string Domain => Request.Domain;
    public string Description => Request.Description;
    public string TimestampDisplay => Request.Timestamp.ToLocalTime().ToString("HH:mm:ss");

    public ElementPickerBlockRequestRow(SpectraNetworkManager.Core.BrowserGuard.ElementPickerBlockRequest request)
    {
        Request = request;
    }
}
