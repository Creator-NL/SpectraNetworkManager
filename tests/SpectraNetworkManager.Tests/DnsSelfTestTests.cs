using System.Net;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Tests;

public class DnsSelfTestTests
{
    [Fact]
    public void TargetFor_ConvertsAnyAddressesToLoopback()
    {
        var anyV4 = new IPEndPoint(IPAddress.Any, 5353);
        var targetV4 = DnsSelfTest.TargetFor(anyV4);
        Assert.Equal(IPAddress.Loopback, targetV4.Address);
        Assert.Equal(5353, targetV4.Port);

        var anyV6 = new IPEndPoint(IPAddress.IPv6Any, 5353);
        var targetV6 = DnsSelfTest.TargetFor(anyV6);
        Assert.Equal(IPAddress.IPv6Loopback, targetV6.Address);
        Assert.Equal(5353, targetV6.Port);

        var specific = new IPEndPoint(IPAddress.Parse("192.168.1.100"), 53);
        var targetSpecific = DnsSelfTest.TargetFor(specific);
        Assert.Equal(IPAddress.Parse("192.168.1.100"), targetSpecific.Address);
    }

    [Fact]
    public async Task RunAsync_UnboundPort_ReturnsFailureCleanly()
    {
        // Port 59999 is highly unlikely to have a DNS server running
        var deadEndpoint = new IPEndPoint(IPAddress.Loopback, 59999);
        var result = await DnsSelfTest.RunAsync(deadEndpoint, "blocked.test", timeout: TimeSpan.FromMilliseconds(500));

        Assert.False(result.Ok);
        Assert.Contains(result.Lines, l => l.Contains("no answer", StringComparison.OrdinalIgnoreCase));
    }
}
