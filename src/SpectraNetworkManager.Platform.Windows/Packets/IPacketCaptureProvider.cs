using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

public interface IPacketCaptureProvider : IDisposable
{
    event Action<CapturedPacket>? PacketCaptured;
    event Action<string>? StatusChanged;

    string ProviderName { get; }
    bool IsRunning { get; }

    Task<bool> StartAsync(string? interfaceIp = null, CancellationToken ct = default);
    Task StopAsync();
}
