using System.Globalization;
using System.Text;

namespace SpectraNetworkManager.Core;

public sealed class PacketRingBuffer
{
    private readonly object _gate = new();
    private readonly CapturedPacket?[] _buffer;
    private int _head;
    private int _count;
    private long _totalPackets;
    private long _totalBytes;

    // Rate calculation
    private long _packetsInLastWindow;
    private DateTimeOffset _lastWindowTime = DateTimeOffset.UtcNow;
    private double _currentRate;

    public int Capacity { get; }
    public long TotalPackets => Interlocked.Read(ref _totalPackets);
    public long TotalBytes => Interlocked.Read(ref _totalBytes);
    public int Count { get { lock (_gate) return _count; } }

    public PacketRingBuffer(int capacity = 10000)
    {
        Capacity = Math.Max(10, capacity);
        _buffer = new CapturedPacket?[Capacity];
    }

    public void Add(CapturedPacket packet)
    {
        lock (_gate)
        {
            _buffer[_head] = packet;
            _head = (_head + 1) % Capacity;
            if (_count < Capacity) _count++;

            _totalPackets++;
            _totalBytes += packet.TotalLength;
            _packetsInLastWindow++;

            var now = DateTimeOffset.UtcNow;
            var elapsed = (now - _lastWindowTime).TotalSeconds;
            if (elapsed >= 1.0)
            {
                _currentRate = _packetsInLastWindow / elapsed;
                _packetsInLastWindow = 0;
                _lastWindowTime = now;
            }
        }
    }

    public void AddRange(IEnumerable<CapturedPacket> packets)
    {
        lock (_gate)
        {
            foreach (var p in packets)
            {
                _buffer[_head] = p;
                _head = (_head + 1) % Capacity;
                if (_count < Capacity) _count++;

                _totalPackets++;
                _totalBytes += p.TotalLength;
                _packetsInLastWindow++;
            }

            var now = DateTimeOffset.UtcNow;
            var elapsed = (now - _lastWindowTime).TotalSeconds;
            if (elapsed >= 1.0)
            {
                _currentRate = _packetsInLastWindow / elapsed;
                _packetsInLastWindow = 0;
                _lastWindowTime = now;
            }
        }
    }

    public List<CapturedPacket> GetSnapshot(PacketFilterOptions? filter = null, int maxItems = 1000)
    {
        var list = new List<CapturedPacket>();
        lock (_gate)
        {
            if (_count == 0) return list;

            int start = (_head - _count + Capacity) % Capacity;
            for (int i = 0; i < _count; i++)
            {
                int idx = (start + i) % Capacity;
                var pkt = _buffer[idx];
                if (pkt == null) continue;

                if (MatchesFilter(pkt, filter))
                {
                    list.Add(pkt);
                }
            }
        }

        // Return latest packets first if count > maxItems
        if (list.Count > maxItems)
        {
            list = list.TakeLast(maxItems).ToList();
        }

        return list;
    }

    private static bool MatchesFilter(CapturedPacket p, PacketFilterOptions? filter)
    {
        if (filter == null) return true;

        if (!string.IsNullOrEmpty(filter.Protocol) && !string.Equals(filter.Protocol, "ALL", StringComparison.OrdinalIgnoreCase))
        {
            if (filter.Protocol.Equals("TLS", StringComparison.OrdinalIgnoreCase) && p.Protocol != PacketProtocol.Tls) return false;
            if (filter.Protocol.Equals("DNS", StringComparison.OrdinalIgnoreCase) && p.Protocol != PacketProtocol.Dns) return false;
            if (filter.Protocol.Equals("HTTP", StringComparison.OrdinalIgnoreCase) && p.Protocol != PacketProtocol.Http) return false;
            if (filter.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) && p.Protocol != PacketProtocol.Tcp && p.Protocol != PacketProtocol.Tls && p.Protocol != PacketProtocol.Http) return false;
            if (filter.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) && p.Protocol != PacketProtocol.Udp && p.Protocol != PacketProtocol.Dns) return false;
        }

        if (filter.Port.HasValue && p.SourcePort != filter.Port.Value && p.DestinationPort != filter.Port.Value)
            return false;

        if (filter.OnlyIdentifiedHosts && string.IsNullOrEmpty(p.HostOrSni))
            return false;

        if (!string.IsNullOrWhiteSpace(filter.SearchText))
        {
            string term = filter.SearchText.Trim();
            bool matches = (p.HostOrSni?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false)
                           || p.SourceAddress.ToString().Contains(term, StringComparison.OrdinalIgnoreCase)
                           || p.DestinationAddress.ToString().Contains(term, StringComparison.OrdinalIgnoreCase)
                           || p.SourcePort.ToString(CultureInfo.InvariantCulture).Contains(term)
                           || p.DestinationPort.ToString(CultureInfo.InvariantCulture).Contains(term)
                           || (p.ProcessName?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false)
                           || p.Info.Contains(term, StringComparison.OrdinalIgnoreCase);

            if (!matches) return false;
        }

        return true;
    }

    public void Clear()
    {
        lock (_gate)
        {
            Array.Clear(_buffer, 0, _buffer.Length);
            _head = 0;
            _count = 0;
            _totalPackets = 0;
            _totalBytes = 0;
            _packetsInLastWindow = 0;
            _currentRate = 0;
        }
    }

    public PacketCaptureStats GetStats(bool isRunning, string providerName)
    {
        lock (_gate)
        {
            return new PacketCaptureStats(
                TotalPackets: _totalPackets,
                TotalBytes: _totalBytes,
                PacketsPerSecond: Math.Round(_currentRate, 1),
                BufferCount: _count,
                BufferCapacity: Capacity,
                IsRunning: isRunning,
                ActiveProvider: providerName);
        }
    }

    public async Task ExportToPcapngAsync(string filePath, PacketFilterOptions? filter = null, CancellationToken ct = default)
    {
        var packets = GetSnapshot(filter, maxItems: Capacity);
        await PcapngWriter.WriteAsync(filePath, packets, ct);
    }

    public async Task ExportToCsvAsync(string filePath, PacketFilterOptions? filter = null, CancellationToken ct = default)
    {
        var packets = GetSnapshot(filter, maxItems: Capacity);
        var sb = new StringBuilder();
        sb.AppendLine("Id,TimestampUtc,Direction,Protocol,Source,Destination,Length,HostOrSni,Process,Info");

        foreach (var p in packets)
        {
            if (ct.IsCancellationRequested) break;
            sb.AppendLine(string.Join(",",
                p.Id,
                p.Timestamp.ToString("o"),
                p.IsInbound ? "INBOUND" : "OUTBOUND",
                p.ProtocolDisplay,
                $"\"{p.SourceEndpointDisplay}\"",
                $"\"{p.DestinationEndpointDisplay}\"",
                p.TotalLength,
                $"\"{p.HostOrSni ?? ""}\"",
                $"\"{p.ProcessDisplay}\"",
                $"\"{p.Info.Replace("\"", "\"\"")}\""));
        }

        await File.WriteAllTextAsync(filePath, sb.ToString(), Encoding.UTF8, ct);
    }
}
