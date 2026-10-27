using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpectraNetworkManager.Core;

public enum DeviceKind
{
    Unknown = 0,
    Workstation = 1,
    SmartTv = 2,
    MobileOrTablet = 3,
    RouterOrGateway = 4,
    Printer = 5,
    IotOrSmartHome = 6,
    ServerOrNas = 7,
}

public enum ScanProfile
{
    PassiveOnly = 0,
    Top20 = 1,
    Top100 = 2,
    Top1000 = 3,
    LocalSockets = 4,
    Custom = 5,
}

public enum PortState
{
    Open,
    Closed,
    Filtered,
}

public sealed record DiscoveredPort(
    int Port,
    Protocol Protocol,
    string ServiceName,
    string Banner,
    int ResponseTimeMs,
    int? OwningPid = null,
    string? OwningProcess = null,
    string? OwningService = null,
    bool IsLocalExposed = false)
{
    public string DisplayString =>
        $"{Port}/{Protocol.ToString().ToUpperInvariant()} ({ServiceName})" +
        (!string.IsNullOrEmpty(OwningProcess) ? $" - {OwningProcess}" : "") +
        (!string.IsNullOrEmpty(OwningService) ? $" [{OwningService}]" : "") +
        (!string.IsNullOrEmpty(Banner) ? $" [{Banner}]" : "");
}

public sealed class DiscoveredDevice
{
    [JsonConverter(typeof(IPAddressJsonConverter))]
    public IPAddress Ip { get; set; } = IPAddress.None;
    public string MacAddress { get; set; } = "";
    public string Vendor { get; set; } = "";
    public string Hostname { get; set; } = "";
    public DeviceKind Kind { get; set; } = DeviceKind.Unknown;
    public string DeviceDescription { get; set; } = "";
    public List<DiscoveredPort> OpenPorts { get; set; } = new();
    public bool IsLocalHost { get; set; }
    public bool IsGateway { get; set; }
    public string ProtectionStatus { get; set; } = "Unprotected";
    public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;

    public string IpString => Ip.ToString();
    public string MacString => string.IsNullOrEmpty(MacAddress) ? "(unknown MAC)" : MacAddress;

    public string KindDisplay => Kind switch
    {
        DeviceKind.SmartTv => "📺 Smart TV / Streaming",
        DeviceKind.MobileOrTablet => "📱 Mobile / Tablet",
        DeviceKind.RouterOrGateway => "🌐 Router / Gateway",
        DeviceKind.Printer => "🖨️ Printer / Scanner",
        DeviceKind.Workstation => "💻 Workstation / PC",
        DeviceKind.IotOrSmartHome => "🔌 IoT / Smart Home",
        DeviceKind.ServerOrNas => "🗄️ Server / NAS",
        _ => "❓ Network Device"
    };

    public string OpenPortsSummary =>
        OpenPorts.Count == 0
            ? "(no open ports found)"
            : string.Join(", ", OpenPorts.Take(6).Select(p => $"{p.Port} ({p.ServiceName})")) +
              (OpenPorts.Count > 6 ? $" (+{OpenPorts.Count - 6} more)" : "");
}

public sealed class IPAddressJsonConverter : JsonConverter<IPAddress>
{
    public override IPAddress? Read(ref Utf8JsonReader reader, Type typeToConvert, System.Text.Json.JsonSerializerOptions options)
    {
        string? s = reader.GetString();
        return string.IsNullOrEmpty(s) ? IPAddress.None : IPAddress.Parse(s);
    }

    public override void Write(Utf8JsonWriter writer, IPAddress value, System.Text.Json.JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}

public sealed record ScanProgressReport(
    int TotalTargets,
    int ScannedTargets,
    int FoundDevices,
    int FoundPorts,
    string CurrentStatus,
    bool IsComplete,
    DiscoveredDevice? NewlyDiscoveredDevice = null,
    string? CurrentProbingIp = null,
    double HostsPerSecond = 0.0,
    TimeSpan? EstimatedTimeRemaining = null)
{
    public double ProgressPercentage => TotalTargets > 0 ? Math.Min(100.0, (ScannedTargets * 100.0) / TotalTargets) : 0.0;
}
