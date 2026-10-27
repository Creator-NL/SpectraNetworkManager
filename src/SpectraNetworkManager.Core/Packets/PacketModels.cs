using System.Net;

namespace SpectraNetworkManager.Core;

public enum PacketProtocol
{
    Other = 0,
    Tcp = 1,
    Udp = 2,
    Icmp = 3,
    IcmpV6 = 4,
    Dns = 5,
    Tls = 6,
    Http = 7
}

public sealed class CapturedPacket
{
    public long Id { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public PacketProtocol Protocol { get; init; }
    public string ProtocolDisplay { get; init; } = "OTHER";
    public IPAddress SourceAddress { get; init; } = IPAddress.Any;
    public int SourcePort { get; init; }
    public IPAddress DestinationAddress { get; init; } = IPAddress.Any;
    public int DestinationPort { get; init; }
    public int TotalLength { get; init; }
    public int PayloadLength { get; init; }
    public bool IsInbound { get; init; }
    public string DirectionDisplay => IsInbound ? "⬅️ IN" : "➡️ OUT";
    public string SourceEndpointDisplay => SourcePort > 0 ? $"{SourceAddress}:{SourcePort}" : SourceAddress.ToString();
    public string DestinationEndpointDisplay => DestinationPort > 0 ? $"{DestinationAddress}:{DestinationPort}" : DestinationAddress.ToString();
    
    public string? HostOrSni { get; init; }
    public string Info { get; init; } = "";
    public string TcpFlags { get; init; } = "";
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string ProcessDisplay => ProcessId.HasValue 
        ? (!string.IsNullOrEmpty(ProcessName) ? $"{ProcessName} [{ProcessId}]" : $"PID {ProcessId}") 
        : "-";

    public byte[] RawData { get; init; } = Array.Empty<byte>();

    public string HexDumpPreview
    {
        get
        {
            if (RawData.Length == 0) return "(No payload data captured)";
            var sb = new System.Text.StringBuilder();
            int bytesToShow = Math.Min(RawData.Length, 256);
            for (int i = 0; i < bytesToShow; i += 16)
            {
                sb.Append($"{i:X4}  ");
                // Hex bytes
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < bytesToShow)
                        sb.Append($"{RawData[i + j]:X2} ");
                    else
                        sb.Append("   ");
                    if (j == 7) sb.Append(' ');
                }
                sb.Append(" |");
                // ASCII chars
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < bytesToShow)
                    {
                        byte b = RawData[i + j];
                        sb.Append(b is >= 32 and <= 126 ? (char)b : '.');
                    }
                }
                sb.AppendLine("|");
            }
            if (RawData.Length > bytesToShow)
            {
                sb.AppendLine($"... ({RawData.Length - bytesToShow} more bytes truncated for preview)");
            }
            return sb.ToString();
        }
    }
}

public sealed record PacketFilterOptions(
    string? Protocol = null,
    int? Port = null,
    string? SearchText = null,
    bool OnlyIdentifiedHosts = false);

public sealed record PacketCaptureStats(
    long TotalPackets,
    long TotalBytes,
    double PacketsPerSecond,
    int BufferCount,
    int BufferCapacity,
    bool IsRunning,
    string ActiveProvider);
