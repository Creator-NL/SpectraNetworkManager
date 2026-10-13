using System.Net;
using NetSentinel.Core;

namespace NetSentinel.Tests;

public class AddressSetTests
{
    [Fact]
    public void Empty_ContainsNothing()
    {
        var set = AddressSet.Empty;
        Assert.True(set.IsEmpty);
        Assert.False(set.Contains(IPAddress.Parse("127.0.0.1")));
        Assert.False(set.Contains(IPAddress.Parse("1.1.1.1")));
    }

    [Fact]
    public void LocalNetwork_ContainsPrivateAndLoopbackRanges()
    {
        var local = AddressSet.LocalNetwork;
        Assert.True(local.Contains(IPAddress.Parse("127.0.0.1")));
        Assert.True(local.Contains(IPAddress.Parse("10.1.2.3")));
        Assert.True(local.Contains(IPAddress.Parse("192.168.1.1")));
        Assert.True(local.Contains(IPAddress.Parse("172.20.0.1")));
        Assert.True(local.Contains(IPAddress.Parse("169.254.1.1")));
        Assert.False(local.Contains(IPAddress.Parse("8.8.8.8")));
        Assert.False(local.Contains(IPAddress.Parse("1.1.1.1")));
    }

    [Fact]
    public void TryParse_SingleIpAndCidr_ContainsExpectedAddresses()
    {
        Assert.True(AddressSet.TryParse("192.168.1.5, 10.0.0.0/24", out var set, out var err), err);
        Assert.NotNull(set);
        Assert.True(set.Contains(IPAddress.Parse("192.168.1.5")));
        Assert.False(set.Contains(IPAddress.Parse("192.168.1.6")));
        Assert.True(set.Contains(IPAddress.Parse("10.0.0.1")));
        Assert.True(set.Contains(IPAddress.Parse("10.0.0.254")));
        Assert.False(set.Contains(IPAddress.Parse("10.0.1.1")));
    }

    [Fact]
    public void TryParse_Range_ContainsExpectedAddresses()
    {
        Assert.True(AddressSet.TryParse("1.2.3.10-1.2.3.20", out var set, out var err), err);
        Assert.NotNull(set);
        Assert.True(set.Contains(IPAddress.Parse("1.2.3.10")));
        Assert.True(set.Contains(IPAddress.Parse("1.2.3.15")));
        Assert.True(set.Contains(IPAddress.Parse("1.2.3.20")));
        Assert.False(set.Contains(IPAddress.Parse("1.2.3.9")));
        Assert.False(set.Contains(IPAddress.Parse("1.2.3.21")));
    }

    [Fact]
    public void Complement_DoubleComplement_EqualsOriginal()
    {
        Assert.True(AddressSet.TryParse("10.0.0.0/16, 192.168.1.1-192.168.1.100, 8.8.8.8", out var set, out var err), err);
        var comp = set.Complement();
        var doubleComp = comp.Complement();

        var testIps = new[]
        {
            "10.0.0.1", "10.0.255.255", "10.1.0.1",
            "192.168.1.1", "192.168.1.50", "192.168.1.101",
            "8.8.8.8", "8.8.8.9", "1.1.1.1", "255.255.255.255", "0.0.0.0"
        };

        foreach (var ipStr in testIps)
        {
            var ip = IPAddress.Parse(ipStr);
            Assert.Equal(set.Contains(ip), doubleComp.Contains(ip));
            Assert.NotEqual(set.Contains(ip), comp.Contains(ip));
        }
    }

    [Fact]
    public void Keywords_And_Ipv6_AreHandled()
    {
        Assert.True(AddressSet.TryParse("LocalSubnet, 2001:db8::1", out var set, out var err), err);
        Assert.NotNull(set);
        Assert.True(set.HasNonIpv4);
        Assert.Throws<InvalidOperationException>(() => set.Complement());
        Assert.Contains("LocalSubnet", set.ToFirewallString());
        Assert.Contains("2001:db8::1", set.ToFirewallString());
    }

    [Theory]
    [InlineData("999.1.1.1")]
    [InlineData("10.0.0.0/33")]
    [InlineData("1.1.1.5-1.1.1.1")]
    [InlineData("invalid-token")]
    public void TryParse_Invalid_ReturnsFalse(string text)
    {
        Assert.False(AddressSet.TryParse(text, out _, out var error));
        Assert.NotEmpty(error);
    }
}
