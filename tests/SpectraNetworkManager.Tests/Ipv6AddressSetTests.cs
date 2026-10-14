using System.Net;
using SpectraNetworkManager.Core;
using Xunit;

namespace SpectraNetworkManager.Tests;

public class Ipv6AddressSetTests
{
    [Fact]
    public void TryParse_SingleAddresses_ParsesCorrectly()
    {
        bool ok = Ipv6AddressSet.TryParse("2001:db8::1, ::1", out var set, out string error);

        Assert.True(ok);
        Assert.Empty(error);
        Assert.Equal(2, set.Ranges.Count);
        Assert.True(set.Contains(IPAddress.Parse("2001:db8::1")));
        Assert.True(set.Contains(IPAddress.Parse("::1")));
        Assert.False(set.Contains(IPAddress.Parse("2001:db8::2")));
    }

    [Fact]
    public void TryParse_CidrBlock_ExpandsCorrectly()
    {
        bool ok = Ipv6AddressSet.TryParse("fe80::/10", out var set, out string error);

        Assert.True(ok);
        Assert.Empty(error);
        Assert.Single(set.Ranges);
        Assert.True(set.Contains(IPAddress.Parse("fe80::1")));
        Assert.True(set.Contains(IPAddress.Parse("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
        Assert.False(set.Contains(IPAddress.Parse("fec0::1")));
    }

    [Fact]
    public void TryParse_Range_ExpandsCorrectly()
    {
        bool ok = Ipv6AddressSet.TryParse("2001:db8::10 - 2001:db8::20", out var set, out string error);

        Assert.True(ok);
        Assert.Empty(error);
        Assert.Single(set.Ranges);
        Assert.True(set.Contains(IPAddress.Parse("2001:db8::10")));
        Assert.True(set.Contains(IPAddress.Parse("2001:db8::15")));
        Assert.True(set.Contains(IPAddress.Parse("2001:db8::20")));
        Assert.False(set.Contains(IPAddress.Parse("2001:db8::9")));
        Assert.False(set.Contains(IPAddress.Parse("2001:db8::21")));
    }

    [Fact]
    public void Merge_OverlappingAndAdjacentRanges_Combines()
    {
        // 2001:db8::1 - 2001:db8::10 and 2001:db8::11 - 2001:db8::20 (adjacent)
        bool ok = Ipv6AddressSet.TryParse("2001:db8::1-2001:db8::10, 2001:db8::11-2001:db8::20", out var set, out _);

        Assert.True(ok);
        Assert.Single(set.Ranges);
        Assert.True(set.Contains(IPAddress.Parse("2001:db8::10")));
        Assert.True(set.Contains(IPAddress.Parse("2001:db8::11")));
    }

    [Fact]
    public void Complement_Empty_CoversAll()
    {
        var comp = Ipv6AddressSet.Empty.Complement();

        Assert.Single(comp.Ranges);
        Assert.Equal(UInt128.Zero, comp.Ranges[0].Start);
        Assert.Equal(UInt128.MaxValue, comp.Ranges[0].End);
        Assert.True(comp.Contains(IPAddress.Parse("::")));
        Assert.True(comp.Contains(IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
    }

    [Fact]
    public void Complement_All_IsEmpty()
    {
        Ipv6AddressSet.TryParse("::/0", out var set, out _);
        var comp = set.Complement();

        Assert.True(comp.IsEmpty);
    }

    [Fact]
    public void Complement_InvertsAddressSet()
    {
        Ipv6AddressSet.TryParse("2001:db8::1", out var set, out _);
        var comp = set.Complement();

        Assert.Equal(2, comp.Ranges.Count);
        Assert.False(comp.Contains(IPAddress.Parse("2001:db8::1")));
        Assert.True(comp.Contains(IPAddress.Parse("2001:db8::2")));
        Assert.True(comp.Contains(IPAddress.Parse("::1")));

        // Double complement returns original
        var doubleComp = comp.Complement();
        Assert.Single(doubleComp.Ranges);
        Assert.Equal(set.Ranges[0], doubleComp.Ranges[0]);
    }

    [Fact]
    public void LocalNetwork_CoversLoopbackLinkLocalULAAndMulticast()
    {
        var local = Ipv6AddressSet.LocalNetwork;

        Assert.True(local.Contains(IPAddress.Parse("::1")));
        Assert.True(local.Contains(IPAddress.Parse("fe80::dead:beef")));
        Assert.True(local.Contains(IPAddress.Parse("fd12:3456:789a::1")));
        Assert.True(local.Contains(IPAddress.Parse("ff02::1")));

        // Public internet IPv6 must NOT be in local network
        Assert.False(local.Contains(IPAddress.Parse("2001:4860:4860::8888")));
        Assert.False(local.Contains(IPAddress.Parse("2606:4700:4700::1111")));
    }
}
