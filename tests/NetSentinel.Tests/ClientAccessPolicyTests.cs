using System.Net;
using NetSentinel.Sinkhole;
using Xunit;

namespace NetSentinel.Tests;

public class ClientAccessPolicyTests
{
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.0.0.53", true)]
    [InlineData("::1", true)]
    [InlineData("10.0.0.1", true)]
    [InlineData("10.254.254.254", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.24.1.1", true)]
    [InlineData("172.31.255.254", true)]
    [InlineData("172.32.0.1", false)]           // Outside RFC 1918 (172.16 - 172.31)
    [InlineData("192.168.0.1", true)]
    [InlineData("192.168.100.254", true)]
    [InlineData("169.254.1.1", true)]           // Link-local
    [InlineData("100.64.0.1", true)]            // RFC 6598 CGNAT
    [InlineData("100.127.255.254", true)]       // RFC 6598 CGNAT
    [InlineData("100.128.0.1", false)]          // Outside CGNAT
    [InlineData("8.8.8.8", false)]              // Public Google DNS
    [InlineData("1.1.1.1", false)]              // Public Cloudflare DNS
    [InlineData("142.250.190.46", false)]       // Public Google IP
    [InlineData("208.67.222.222", false)]       // Public OpenDNS
    [InlineData("fe80::1", true)]               // IPv6 link-local
    [InlineData("fc00::1", true)]               // IPv6 ULA
    [InlineData("fd12:3456:789a::1", true)]     // IPv6 ULA
    [InlineData("2606:4700:4700::1111", false)] // Public IPv6 Cloudflare
    [InlineData("2001:4860:4860::8888", false)] // Public IPv6 Google
    public void DefaultPolicy_OnlyPermitsLoopbackAndPrivateRanges(string ipStr, bool expectedAllowed)
    {
        var policy = new ClientAccessPolicy(restrictToLocal: true);
        var ip = IPAddress.Parse(ipStr);

        bool allowed = policy.IsAllowed(ip);

        Assert.Equal(expectedAllowed, allowed);
    }

    [Theory]
    [InlineData("::ffff:127.0.0.1", true)]
    [InlineData("::ffff:192.168.1.50", true)]
    [InlineData("::ffff:10.0.0.5", true)]
    [InlineData("::ffff:8.8.8.8", false)]
    [InlineData("::ffff:1.1.1.1", false)]
    public void IPv4MappedToIPv6_HandledCorrectly(string ipStr, bool expectedAllowed)
    {
        var policy = new ClientAccessPolicy(restrictToLocal: true);
        var ip = IPAddress.Parse(ipStr);

        Assert.True(ip.IsIPv4MappedToIPv6);
        bool allowed = policy.IsAllowed(ip);

        Assert.Equal(expectedAllowed, allowed);
    }

    [Fact]
    public void PolicyDisabled_PermitsPublicIPs()
    {
        var policy = new ClientAccessPolicy(restrictToLocal: false);

        Assert.True(policy.IsAllowed(IPAddress.Parse("8.8.8.8")));
        Assert.True(policy.IsAllowed(IPAddress.Parse("2606:4700::1")));
        Assert.True(policy.IsAllowed(IPAddress.Loopback));
    }

    [Fact]
    public void CustomAllowedRanges_PermitConfiguredPublicCidr()
    {
        var customRange = new[] { "198.51.100.0/24", "2001:db8::/32" };
        var policy = new ClientAccessPolicy(restrictToLocal: true, customAllowedRanges: customRange);

        Assert.True(policy.IsAllowed(IPAddress.Parse("198.51.100.42")));
        Assert.True(policy.IsAllowed(IPAddress.Parse("2001:db8::beef")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("198.51.101.1")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("8.8.8.8")));
    }
}
