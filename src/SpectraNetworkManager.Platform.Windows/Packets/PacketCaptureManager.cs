using System.Collections.Concurrent;
using System.Net;
using System.Runtime.Versioning;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

[SupportedOSPlatform("windows")]
public sealed class PacketCaptureManager : IDisposable
{
    private readonly IPacketCaptureProvider _provider;
    private readonly PacketRingBuffer _ringBuffer;
    private readonly ConcurrentQueue<CapturedPacket> _incomingQueue = new();
    private readonly System.Timers.Timer _flushTimer;
    private readonly Func<IPAddress, int, IPAddress, int, Protocol, (int? Pid, string? Name)>? _connectionMatcher;

    public event Action<IReadOnlyList<CapturedPacket>, PacketCaptureStats>? BatchFlushed;
    public event Action<string>? StatusChanged;

    public PacketRingBuffer Buffer => _ringBuffer;
    public bool IsRunning => _provider.IsRunning;
    public string ActiveProviderName => _provider.ProviderName;

    public PacketCaptureManager(
        Func<IPAddress, int, IPAddress, int, Protocol, (int? Pid, string? Name)>? connectionMatcher = null,
        int bufferCapacity = 10000)
    {
        _connectionMatcher = connectionMatcher;
        _ringBuffer = new PacketRingBuffer(bufferCapacity);

        // Auto-select provider with process attribution enricher
        _provider = new WindowsPktmonCaptureProvider(EnrichPacketWithProcess);
        _provider.PacketCaptured += OnPacketCaptured;
        _provider.StatusChanged += s => StatusChanged?.Invoke(s);

        // Batch flush timer: 250ms interval for smooth UI performance without CPU spikes
        _flushTimer = new System.Timers.Timer(250) { AutoReset = true };
        _flushTimer.Elapsed += (_, _) => FlushBatch();
    }

    public async Task<bool> StartAsync(string? interfaceIp = null)
    {
        bool started = await _provider.StartAsync(interfaceIp);
        if (started)
        {
            _flushTimer.Start();
        }
        return started;
    }

    public async Task StopAsync()
    {
        _flushTimer.Stop();
        await _provider.StopAsync();
        FlushBatch(); // Flush any remaining queued packets
    }

    private void OnPacketCaptured(CapturedPacket packet)
    {
        _incomingQueue.Enqueue(packet);
    }

    private void EnrichPacketWithProcess(CapturedPacket packet)
    {
        if (_connectionMatcher == null) return;

        Protocol? coreProto = packet.Protocol switch
        {
            PacketProtocol.Tcp or PacketProtocol.Tls or PacketProtocol.Http => Protocol.Tcp,
            PacketProtocol.Udp or PacketProtocol.Dns => Protocol.Udp,
            _ => null
        };

        if (!coreProto.HasValue) return;

        // Try local -> remote match
        var (pid, name) = _connectionMatcher(packet.SourceAddress, packet.SourcePort, packet.DestinationAddress, packet.DestinationPort, coreProto.Value);
        if (pid.HasValue)
        {
            packet.ProcessId = pid;
            packet.ProcessName = name;
            return;
        }

        // Try reverse remote -> local match
        (pid, name) = _connectionMatcher(packet.DestinationAddress, packet.DestinationPort, packet.SourceAddress, packet.SourcePort, coreProto.Value);
        if (pid.HasValue)
        {
            packet.ProcessId = pid;
            packet.ProcessName = name;
        }
    }

    private void FlushBatch()
    {
        if (_incomingQueue.IsEmpty) return;

        var batch = new List<CapturedPacket>();
        while (_incomingQueue.TryDequeue(out var pkt) && batch.Count < 2000)
        {
            batch.Add(pkt);
        }

        if (batch.Count > 0)
        {
            _ringBuffer.AddRange(batch);
            var stats = _ringBuffer.GetStats(IsRunning, ActiveProviderName);
            BatchFlushed?.Invoke(batch, stats);
        }
    }

    public void Clear()
    {
        while (_incomingQueue.TryDequeue(out _)) { }
        _ringBuffer.Clear();
        var stats = _ringBuffer.GetStats(IsRunning, ActiveProviderName);
        BatchFlushed?.Invoke(Array.Empty<CapturedPacket>(), stats);
    }

    public PacketCaptureStats GetStats() =>
        _ringBuffer.GetStats(IsRunning, ActiveProviderName);

    public Task ExportPcapngAsync(string filePath, PacketFilterOptions? filter = null) =>
        _ringBuffer.ExportToPcapngAsync(filePath, filter);

    public Task ExportCsvAsync(string filePath, PacketFilterOptions? filter = null) =>
        _ringBuffer.ExportToCsvAsync(filePath, filter);

    public void Dispose()
    {
        _flushTimer.Dispose();
        _provider.Dispose();
    }
}
