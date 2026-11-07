using System.Net;
using System.Text.Json;
using SpectraNetworkManager.Core;
using Xunit;

namespace SpectraNetworkManager.Tests;

public sealed class NetworkScannerAndClassificationTests
{
    [Fact]
    public void DeviceClassifier_AccuratelyIdentifiesSmartTvs()
    {
        // Roku by MAC prefix
        var (kindRoku, vendorRoku, _) = DeviceClassifier.Classify("B0:EE:7B:11:22:33", "", null);
        Assert.Equal(DeviceKind.SmartTv, kindRoku);
        Assert.Contains("Roku", vendorRoku);

        // LG WebOS by MAC
        var (kindLg, vendorLg, _) = DeviceClassifier.Classify("00:E0:91:AA:BB:CC", "", null);
        Assert.Equal(DeviceKind.SmartTv, kindLg);
        Assert.Contains("LG", vendorLg);

        // Samsung TV by hostname
        var (kindSam, _, descSam) = DeviceClassifier.Classify("", "Samsung-QLED-TV-LivingRoom", null);
        Assert.Equal(DeviceKind.SmartTv, kindSam);
        Assert.Contains("Smart TV", descSam);

        // Apple TV by hostname
        var (kindAppleTv, _, _) = DeviceClassifier.Classify("", "Apple-TV-Bedroom", null);
        Assert.Equal(DeviceKind.SmartTv, kindAppleTv);

        // Roku by open ECP port (8060)
        var ports = new List<DiscoveredPort> { new(8060, Protocol.Tcp, "Roku-ECP", "Roku ECP", 5) };
        var (kindPort, _, _) = DeviceClassifier.Classify("", "", ports);
        Assert.Equal(DeviceKind.SmartTv, kindPort);
    }

    [Fact]
    public void DeviceClassifier_AccuratelyIdentifiesMobileAndTablets()
    {
        // Apple iPhone / iPad MAC
        var (kindApple, vendorApple, _) = DeviceClassifier.Classify("00:1C:B3:12:34:56", "", null);
        Assert.Equal(DeviceKind.MobileOrTablet, kindApple);
        Assert.Contains("Apple", vendorApple);

        // Android hostname
        var (kindAndroid, _, _) = DeviceClassifier.Classify("", "Galaxy-S24-Ultra", null);
        Assert.Equal(DeviceKind.MobileOrTablet, kindAndroid);

        // Pixel hostname
        var (kindPixel, _, _) = DeviceClassifier.Classify("", "android-pixel-7", null);
        Assert.Equal(DeviceKind.MobileOrTablet, kindPixel);
    }

    [Fact]
    public void DeviceClassifier_IdentifiesRoutersPrintersAndIot()
    {
        // Router by gateway flag
        var (kindGw, _, _) = DeviceClassifier.Classify("", "", null, isGateway: true);
        Assert.Equal(DeviceKind.RouterOrGateway, kindGw);

        // AVM Fritz!Box by MAC
        var (kindFritz, vendorFritz, _) = DeviceClassifier.Classify("C0:25:06:12:34:56", "", null);
        Assert.Equal(DeviceKind.RouterOrGateway, kindFritz);
        Assert.Contains("AVM Fritz!", vendorFritz);

        // Printer by JetDirect port (9100)
        var printerPorts = new List<DiscoveredPort> { new(9100, Protocol.Tcp, "RAW-JetDirect", "", 10) };
        var (kindPrinter, _, _) = DeviceClassifier.Classify("", "", printerPorts);
        Assert.Equal(DeviceKind.Printer, kindPrinter);

        // Espressif ESP32 IoT chip
        var (kindEsp, vendorEsp, _) = DeviceClassifier.Classify("24:0A:C4:AA:BB:CC", "", null);
        Assert.Equal(DeviceKind.IotOrSmartHome, kindEsp);
        Assert.Contains("Espressif", vendorEsp);
    }

    [Fact]
    public void NetworkScanner_IsPrivateOrLocal_CorrectlyDifferentiatesIps()
    {
        Assert.True(NetworkScanner.IsPrivateOrLocal(IPAddress.Loopback));
        Assert.True(NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("192.168.1.1")));
        Assert.True(NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("10.0.5.20")));
        Assert.True(NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("172.16.10.1")));
        Assert.True(NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("169.254.1.1"))); // Link-local
        Assert.True(NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("100.64.1.1")));  // CGNAT

        // Public WAN IPs require confirmation
        Assert.False(NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("8.8.8.8")));
        Assert.False(NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("1.1.1.1")));
        Assert.False(NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("142.250.190.46")));
    }

    [Fact]
    public void NetworkScanner_GenerateSubnetIps_Produces254Hosts()
    {
        var ips = NetworkScanner.GenerateSubnetIps(IPAddress.Parse("192.168.178.55"));
        Assert.Equal(254, ips.Count);
        Assert.Equal("192.168.178.1", ips.First().ToString());
        Assert.Equal("192.168.178.254", ips.Last().ToString());
    }

    [Fact]
    public void WellKnownPorts_ProvidesTopListsAndServiceNames()
    {
        Assert.Equal(20, WellKnownPorts.Top20.Length);
        Assert.Equal(100, WellKnownPorts.Top100.Length);

        Assert.Equal("HTTP", WellKnownPorts.GetServiceName(80, Protocol.Tcp));
        Assert.Equal("HTTPS", WellKnownPorts.GetServiceName(443, Protocol.Tcp));
        Assert.Equal("DNS", WellKnownPorts.GetServiceName(53, Protocol.Udp));
        Assert.Equal("SSH", WellKnownPorts.GetServiceName(22, Protocol.Tcp));
        Assert.Equal("RDP / Remote Desktop", WellKnownPorts.GetServiceName(3389, Protocol.Tcp));
    }

    [Fact]
    public void LocalSocketInventory_InventoriesListeningSockets()
    {
        var fakeSource = new FakeConnectionSource(new List<ConnectionInfo>
        {
            new(Protocol.Tcp, new IPEndPoint(IPAddress.Any, 8080), new IPEndPoint(IPAddress.Any, 0), ConnectionState.Listen, 1234),
            new(Protocol.Tcp, new IPEndPoint(IPAddress.Loopback, 5000), new IPEndPoint(IPAddress.Loopback, 0), ConnectionState.Listen, 5678),
            new(Protocol.Tcp, new IPEndPoint(IPAddress.Parse("192.168.1.10"), 49152), new IPEndPoint(IPAddress.Parse("1.1.1.1"), 443), ConnectionState.Established, 9999),
        });

        var fakeResolver = new FakeProcessResolver();
        var inventory = new LocalSocketInventory(fakeSource, fakeResolver);

        var device = inventory.GetLocalInventory();
        Assert.True(device.IsLocalHost);
        Assert.Equal(2, device.OpenPorts.Count); // Only the 2 listening sockets, not the ESTABLISHED outbound

        var exposedPort = device.OpenPorts.FirstOrDefault(p => p.Port == 8080);
        Assert.NotNull(exposedPort);
        Assert.True(exposedPort!.IsLocalExposed);

        var loopbackPort = device.OpenPorts.FirstOrDefault(p => p.Port == 5000);
        Assert.NotNull(loopbackPort);
        Assert.False(loopbackPort!.IsLocalExposed);
    }

    [Fact]
    public void NetworkScanner_ExportToCsvAndJson_ProducesValidOutput()
    {
        var devices = new List<DiscoveredDevice>
        {
            new()
            {
                Ip = IPAddress.Parse("192.168.1.1"),
                MacAddress = "00:11:22:33:44:55",
                Vendor = "Netgear",
                Hostname = "router.lan",
                Kind = DeviceKind.RouterOrGateway,
                DeviceDescription = "Default Gateway",
                IsGateway = true,
                ProtectionStatus = "Protected",
                OpenPorts = new List<DiscoveredPort>
                {
                    new(80, Protocol.Tcp, "HTTP", "Lighttpd", 5),
                    new(443, Protocol.Tcp, "HTTPS", "", 10)
                }
            }
        };

        // Test CSV
        using var csvSw = new StringWriter();
        NetworkScanner.ExportToCsv(devices, csvSw);
        string csv = csvSw.ToString();
        Assert.Contains("Type,IP,Hostname,MAC,Vendor", csv);
        Assert.Contains("192.168.1.1", csv);
        Assert.Contains("Netgear", csv);
        Assert.Contains("80/Tcp;443/Tcp", csv);

        // Test JSON
        using var jsonSw = new StringWriter();
        NetworkScanner.ExportToJson(devices, jsonSw);
        string json = jsonSw.ToString();
        Assert.Contains("192.168.1.1", json);
        Assert.Contains("Netgear", json);

        var parsed = JsonSerializer.Deserialize<List<DiscoveredDevice>>(json);
        Assert.NotNull(parsed);
        Assert.Single(parsed!);
        Assert.Equal("192.168.1.1", parsed![0].IpString);
    }

    private sealed class FakeConnectionSource : IConnectionSource
    {
        private readonly IReadOnlyList<ConnectionInfo> _conns;
        public FakeConnectionSource(IReadOnlyList<ConnectionInfo> conns) => _conns = conns;
        public IReadOnlyList<ConnectionInfo> GetConnections() => _conns;
    }

    private sealed class FakeProcessResolver : IProcessResolver
    {
        public ProcessInfo Resolve(int pid) =>
            new(pid, "FakeApp", "C:\\FakeApp.exe", null, null, null, null, null);

        public void Prune(IReadOnlySet<int> livePids) { }
    }
}
