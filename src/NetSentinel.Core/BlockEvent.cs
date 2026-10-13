namespace NetSentinel.Core;

/// <summary>A connection or packet that the Windows Filtering Platform (Windows Firewall) blocked.</summary>
public sealed record BlockEvent(
    long RecordId,
    DateTimeOffset Time,
    int ProcessId,
    string Application,
    bool Inbound,
    string SourceAddress,
    int SourcePort,
    string DestinationAddress,
    int DestinationPort,
    int ProtocolNumber,
    bool IsPacketDrop)
{
    public string ProtocolName => ProtocolNumber switch { 1 => "ICMP", 6 => "TCP", 17 => "UDP", 58 => "ICMPv6", _ => $"proto {ProtocolNumber}" };
}
