using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Platform.Windows;

/// <summary>
/// Detailed network adapter information including current DNS configuration.
/// </summary>
public sealed record NetworkAdapterDnsInfo(
    int InterfaceIndex,
    string Name,
    string Description,
    string Guid,
    string Status,
    bool IsVirtual,
    bool IsWireless,
    IReadOnlyList<string> Ipv4Servers,
    bool Ipv4IsDhcp,
    IReadOnlyList<string> Ipv6Servers,
    bool Ipv6IsDhcp);

/// <summary>
/// Abstraction for querying and modifying system adapter DNS settings.
/// </summary>
public interface ISystemDnsSwitch
{
    Task<IReadOnlyList<NetworkAdapterDnsInfo>> GetAdaptersAsync(CancellationToken ct = default);
    Task ApplyDnsAsync(IEnumerable<int> interfaceIndexes, bool onlyLocal, IReadOnlyList<AdapterDnsBackup> backups, CancellationToken ct = default);
    Task RestoreDnsAsync(IReadOnlyList<AdapterDnsBackup> backups, CancellationToken ct = default);
}
