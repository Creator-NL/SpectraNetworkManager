using System.Net;

namespace SpectraNetworkManager.Core;

/// <summary>
/// Inventories all open listening sockets (TCP) and bound endpoints (UDP) on the local PC,
/// mapping each socket to its owning process, Windows service, and exposure level.
/// </summary>
public sealed class LocalSocketInventory
{
    private readonly IConnectionSource _connections;
    private readonly IProcessResolver _resolver;

    public LocalSocketInventory(IConnectionSource connections, IProcessResolver resolver)
    {
        _connections = connections;
        _resolver = resolver;
    }

    public DiscoveredDevice GetLocalInventory()
    {
        IReadOnlyList<ConnectionInfo> rawConnections;
        try
        {
            rawConnections = _connections.GetConnections();
        }
        catch
        {
            rawConnections = Array.Empty<ConnectionInfo>();
        }
        var ports = new List<DiscoveredPort>();

        var listening = rawConnections
            .Where(c => (c.Protocol == Protocol.Tcp && c.State == ConnectionState.Listen) ||
                        (c.Protocol == Protocol.Udp && (c.Remote is null || c.Remote.Port == 0)))
            .ToList();

        foreach (var c in listening)
        {
            var proc = _resolver.Resolve(c.ProcessId);
            string svcName = WellKnownPorts.GetServiceName(c.Local.Port, c.Protocol);
            bool isExposed = !IPAddress.IsLoopback(c.Local.Address);

            var port = new DiscoveredPort(
                c.Local.Port,
                c.Protocol,
                svcName,
                isExposed ? "LAN / Public Exposed" : "Loopback Only (Safe)",
                0,
                c.ProcessId,
                proc.Name,
                proc.ServiceNames,
                isExposed);

            ports.Add(port);
        }

        // Distinct by Protocol + Port + ProcessId to avoid duplicates
        var distinctPorts = ports
            .OrderBy(p => p.Port)
            .GroupBy(p => (p.Port, p.Protocol, p.OwningPid))
            .Select(g => g.First())
            .ToList();

        return new DiscoveredDevice
        {
            Ip = IPAddress.Loopback,
            MacAddress = "00-00-00-00-00-00",
            Vendor = "Local System",
            Hostname = Environment.MachineName,
            Kind = DeviceKind.Workstation,
            DeviceDescription = $"Local Machine ({Environment.MachineName})",
            OpenPorts = distinctPorts,
            IsLocalHost = true,
            IsGateway = false,
            ProtectionStatus = "Localhost",
            FirstSeen = DateTimeOffset.UtcNow,
            LastSeen = DateTimeOffset.UtcNow,
        };
    }
}
