using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace SpectraNetworkManager.Core;

public interface INeighborScanner
{
    IReadOnlyList<(IPAddress Ip, string Mac, bool IsGateway)> GetNeighborTable();
    Task<string?> ProbeMacAddressAsync(IPAddress ip);
}

/// <summary>
/// Native C# asynchronous, rate-limited network and port scanner.
/// Performs bounded active scans, passive discovery, banner grabbing, and CSV/JSON export.
/// </summary>
public sealed class NetworkScanner
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    private readonly INeighborScanner? _neighborScanner;

    public NetworkScanner(INeighborScanner? neighborScanner = null)
    {
        _neighborScanner = neighborScanner;
    }

    /// <summary>
    /// Checks whether an address is private/local. Scans to public WAN IPs require explicit confirmation.
    /// </summary>
    public static bool IsPrivateOrLocal(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            return true;

        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = address.GetAddressBytes();
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true; // Link-local
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true; // CGNAT
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal) return true;
            byte[] b = address.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC) return true; // ULA
        }

        return false;
    }

    /// <summary>
    /// Generates candidate IPv4 host addresses for a standard /24 subnet containing the given IP.
    /// </summary>
    public static List<IPAddress> GenerateSubnetIps(IPAddress baseIp)
    {
        var list = new List<IPAddress>();
        if (baseIp.AddressFamily != AddressFamily.InterNetwork) return list;

        byte[] b = baseIp.GetAddressBytes();
        for (int i = 1; i <= 254; i++)
        {
            list.Add(new IPAddress(new byte[] { b[0], b[1], b[2], (byte)i }));
        }
        return list;
    }

    /// <summary>
    /// Performs passive discovery by reading neighbor tables (ARP) and observed DNS client activity.
    /// Does not transmit active network probes.
    /// </summary>
    public List<DiscoveredDevice> DiscoverPassive(
        IEnumerable<string>? knownDnsClients = null,
        IPAddress? localIp = null,
        IPAddress? gatewayIp = null)
    {
        var devicesByIp = new Dictionary<string, DiscoveredDevice>(StringComparer.OrdinalIgnoreCase);

        // 1. Add Local Machine
        if (localIp is not null)
        {
            devicesByIp[localIp.ToString()] = new DiscoveredDevice
            {
                Ip = localIp,
                MacAddress = "",
                Vendor = "Local System",
                Hostname = Environment.MachineName,
                Kind = DeviceKind.Workstation,
                DeviceDescription = "This PC (Local Host)",
                IsLocalHost = true,
                IsGateway = false,
                ProtectionStatus = "Localhost",
            };
        }

        // 2. Read ARP Neighbor Table
        if (_neighborScanner != null)
        {
            try
            {
                var neighbors = _neighborScanner.GetNeighborTable();
                foreach (var (ip, mac, isGw) in neighbors)
                {
                    if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.Broadcast))
                        continue;

                    string ipKey = ip.ToString();
                    bool isGatewayDevice = isGw || (gatewayIp is not null && gatewayIp.Equals(ip));

                    var (kind, vendor, desc) = DeviceClassifier.Classify(mac, "", null, isGatewayDevice);

                    devicesByIp[ipKey] = new DiscoveredDevice
                    {
                        Ip = ip,
                        MacAddress = mac,
                        Vendor = vendor,
                        Hostname = "",
                        Kind = kind,
                        DeviceDescription = desc,
                        IsLocalHost = false,
                        IsGateway = isGatewayDevice,
                        ProtectionStatus = "Unprotected",
                    };
                }
            }
            catch
            {
                // Best effort
            }
        }

        // 3. Merge known DNS sinkhole clients
        if (knownDnsClients != null)
        {
            foreach (var client in knownDnsClients)
            {
                string clean = client.Trim();
                if (IPAddress.TryParse(clean, out var clientIp) && !devicesByIp.ContainsKey(clean))
                {
                    bool isGw = gatewayIp is not null && gatewayIp.Equals(clientIp);
                    devicesByIp[clean] = new DiscoveredDevice
                    {
                        Ip = clientIp,
                        MacAddress = "",
                        Vendor = "DNS Client",
                        Hostname = "",
                        Kind = isGw ? DeviceKind.RouterOrGateway : DeviceKind.Unknown,
                        DeviceDescription = "Active DNS Client",
                        IsLocalHost = localIp is not null && localIp.Equals(clientIp),
                        IsGateway = isGw,
                        ProtectionStatus = "Protected (DNS Active)",
                    };
                }
            }
        }

        return devicesByIp.Values.OrderBy(d => d.Ip.ToString()).ToList();
    }

    /// <summary>
    /// Performs an active, rate-limited TCP connect port scan on target IPs.
    /// </summary>
    public async Task<List<DiscoveredDevice>> ScanActiveAsync(
        IReadOnlyList<IPAddress> targets,
        IReadOnlyList<int> ports,
        int timeoutMs = 300,
        int maxConcurrency = 35,
        bool grabBanners = true,
        IPAddress? gatewayIp = null,
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var results = new List<DiscoveredDevice>();
        int totalHosts = targets.Count;
        int scannedHosts = 0;
        int foundPorts = 0;

        using var semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);

        for (int i = 0; i < targets.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var targetIp = targets[i];

            progress?.Report(new ScanProgressReport(
                totalHosts,
                scannedHosts,
                results.Count,
                foundPorts,
                $"Scanning host {targetIp} ({i + 1}/{totalHosts})...",
                false));

            // Check host responsiveness with quick port check or ARP probe
            string? mac = null;
            if (_neighborScanner != null)
            {
                try { mac = await _neighborScanner.ProbeMacAddressAsync(targetIp); } catch { }
            }

            var openPortsOnHost = new List<DiscoveredPort>();

            // Scan selected ports with concurrency limiter
            var portTasks = ports.Select(async port =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    var res = await ProbePortAsync(targetIp, port, timeoutMs, grabBanners, cancellationToken);
                    if (res is not null)
                    {
                        lock (openPortsOnHost)
                        {
                            openPortsOnHost.Add(res);
                            Interlocked.Increment(ref foundPorts);
                        }
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(portTasks);

            scannedHosts++;

            // If any ports are open OR an active MAC address responded
            if (openPortsOnHost.Count > 0 || !string.IsNullOrEmpty(mac))
            {
                string hostname = "";
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(targetIp).WaitAsync(TimeSpan.FromMilliseconds(400), cancellationToken);
                    hostname = hostEntry.HostName ?? "";
                }
                catch { }

                bool isGw = gatewayIp is not null && gatewayIp.Equals(targetIp);
                var (kind, vendor, desc) = DeviceClassifier.Classify(mac ?? "", hostname, openPortsOnHost, isGw);

                var device = new DiscoveredDevice
                {
                    Ip = targetIp,
                    MacAddress = mac ?? "",
                    Vendor = vendor,
                    Hostname = hostname,
                    Kind = kind,
                    DeviceDescription = desc,
                    OpenPorts = openPortsOnHost.OrderBy(p => p.Port).ToList(),
                    IsLocalHost = IPAddress.IsLoopback(targetIp),
                    IsGateway = isGw,
                    ProtectionStatus = "Unprotected",
                    FirstSeen = DateTimeOffset.UtcNow,
                    LastSeen = DateTimeOffset.UtcNow,
                };

                results.Add(device);
            }

            progress?.Report(new ScanProgressReport(
                totalHosts,
                scannedHosts,
                results.Count,
                foundPorts,
                $"Scanned {scannedHosts}/{totalHosts} hosts. Found {results.Count} active devices.",
                false));
        }

        progress?.Report(new ScanProgressReport(
            totalHosts,
            totalHosts,
            results.Count,
            foundPorts,
            $"Scan complete. Found {results.Count} active devices and {foundPorts} open ports.",
            true));

        return results;
    }

    private static async Task<DiscoveredPort?> ProbePortAsync(
        IPAddress ip,
        int port,
        int timeoutMs,
        bool grabBanner,
        CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);

            using var client = new TcpClient(ip.AddressFamily);
            await client.ConnectAsync(ip, port, cts.Token);
            sw.Stop();

            string svcName = WellKnownPorts.GetServiceName(port, Protocol.Tcp);
            string banner = "";
            if (grabBanner)
            {
                banner = await WellKnownPorts.TryGrabBannerAsync(ip, port, Math.Min(250, timeoutMs));
            }

            return new DiscoveredPort(
                port,
                Protocol.Tcp,
                svcName,
                banner,
                (int)sw.ElapsedMilliseconds);
        }
        catch
        {
            return null;
        }
    }

    public static void ExportToCsv(IEnumerable<DiscoveredDevice> devices, TextWriter writer)
    {
        writer.WriteLine("Type,IP,Hostname,MAC,Vendor,Description,OpenPorts,ProtectionStatus");
        foreach (var d in devices)
        {
            string ports = string.Join(";", d.OpenPorts.Select(p => $"{p.Port}/{p.Protocol}"));
            writer.WriteLine(
                $"\"{EscapeCsv(d.Kind.ToString())}\"," +
                $"\"{EscapeCsv(d.IpString)}\"," +
                $"\"{EscapeCsv(d.Hostname)}\"," +
                $"\"{EscapeCsv(d.MacAddress)}\"," +
                $"\"{EscapeCsv(d.Vendor)}\"," +
                $"\"{EscapeCsv(d.DeviceDescription)}\"," +
                $"\"{EscapeCsv(ports)}\"," +
                $"\"{EscapeCsv(d.ProtectionStatus)}\"");
        }
    }

    public static void ExportToJson(IEnumerable<DiscoveredDevice> devices, TextWriter writer)
    {
        writer.Write(JsonSerializer.Serialize(devices, JsonOpts));
    }

    private static string EscapeCsv(string s) => (s ?? "").Replace("\"", "\"\"");
}
