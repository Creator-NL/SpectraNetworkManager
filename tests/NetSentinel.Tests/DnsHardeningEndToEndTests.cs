using System.Net;
using NetSentinel.Sinkhole;
using Xunit;

namespace NetSentinel.Tests;

public class DnsHardeningEndToEndTests
{
    [Fact]
    public async Task HandleAsync_PublicClientIp_IsRefused()
    {
        var settings = new DnsSettings
        {
            RestrictClientsToLocalNetwork = true,
        };
        var filter = DomainFilter.Empty;
        var upstream = new FakeUpstream();
        var cache = new DnsCache(100);
        var activity = new DnsActivity();

        using var server = new DnsServer(settings, () => filter, upstream, cache, activity);

        byte[] rawQuery = DnsWire.BuildQuery("example.com", DnsType.A, 0x4321);
        var publicClient = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 54321);

        byte[]? response = await server.HandleAsync(rawQuery, publicClient, tcp: false, CancellationToken.None);

        Assert.NotNull(response);
        int rcode = DnsWire.ResponseRcode(response);
        Assert.Equal(DnsRcode.Refused, rcode);

        // Verify activity logged as Refused
        var recent = activity.Recent(1);
        Assert.Single(recent);
        Assert.Equal(DnsOutcome.Refused, recent[0].Outcome);
        Assert.Contains("public/untrusted", recent[0].Detail);
    }

    [Fact]
    public async Task HandleAsync_PrivateClientIp_IsAccepted()
    {
        var settings = new DnsSettings
        {
            RestrictClientsToLocalNetwork = true,
        };
        var filter = DomainFilter.Empty;
        var upstream = new FakeUpstream
        {
            Handler = (q, isTcp) =>
            {
                if (DnsQuery.TryParse(q, out var query, out string err) && query is not null)
                {
                    return DnsWire.BuildResponse(query, DnsRcode.NoError, new[]
                    {
                        (DnsType.A, new byte[] { 93, 184, 216, 34 })
                    });
                }
                return null;
            }
        };
        var cache = new DnsCache(100);
        var activity = new DnsActivity();

        using var server = new DnsServer(settings, () => filter, upstream, cache, activity);

        byte[] rawQuery = DnsWire.BuildQuery("example.com", DnsType.A, 0x4321);
        var privateClient = new IPEndPoint(IPAddress.Parse("192.168.1.150"), 54321);

        byte[]? response = await server.HandleAsync(rawQuery, privateClient, tcp: false, CancellationToken.None);

        Assert.NotNull(response);
        int rcode = DnsWire.ResponseRcode(response);
        Assert.Equal(DnsRcode.NoError, rcode);

        var recent = activity.Recent(1);
        Assert.Single(recent);
        Assert.Equal(DnsOutcome.Forwarded, recent[0].Outcome);
    }

    [Fact]
    public async Task HandleAsync_AnyQuery_ReturnsRfc8482MinimalHinfo()
    {
        var settings = new DnsSettings();
        var filter = DomainFilter.Empty;
        var upstream = new FakeUpstream();
        var cache = new DnsCache(100);
        var activity = new DnsActivity();

        using var server = new DnsServer(settings, () => filter, upstream, cache, activity);

        byte[] rawQuery = DnsWire.BuildQuery("example.com", DnsType.ANY, 0x9999);
        var client = new IPEndPoint(IPAddress.Loopback, 54321);

        byte[]? response = await server.HandleAsync(rawQuery, client, tcp: false, CancellationToken.None);

        Assert.NotNull(response);
        int rcode = DnsWire.ResponseRcode(response);
        Assert.Equal(DnsRcode.NoError, rcode);

        // Upstream was never queried for ANY (prevent amplification)
        Assert.Equal(0, upstream.CallCount);

        var recent = activity.Recent(1);
        Assert.Single(recent);
        Assert.Contains("RFC 8482", recent[0].Detail);
    }
}
