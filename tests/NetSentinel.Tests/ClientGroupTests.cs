using System.Net;
using NetSentinel.Sinkhole;

namespace NetSentinel.Tests;

public sealed class ClientGroupTests
{
    [Fact]
    public async Task ClientGroups_CanDisableBlockingPerClient()
    {
        var builder = new DomainFilterBuilder();
        builder.AddBlock("ads.example.com");
        var baseFilter = builder.Build();

        var settings = new DnsSettings
        {
            ClientGroups = new List<ClientGroup>
            {
                new()
                {
                    Name = "ExemptDevice",
                    ClientRanges = new List<string> { "192.168.1.50" },
                    BlockingEnabled = false
                }
            }
        };

        var fakeUpstream = new FakeUpstream
        {
            Handler = (raw, _) => DnsWire.BuildResponse(
                DnsQuery.TryParse(raw, out var q, out string _) ? q! : null!,
                DnsRcode.NoError,
                new[] { (DnsType.A, new byte[] { 1, 2, 3, 4 }) }
            )
        };

        var cache = new DnsCache(100);
        var activity = new DnsActivity();
        var clientPolicy = new ClientAccessPolicy(restrictToLocal: false);

        using var server = new DnsServer(
            settings,
            () => baseFilter,
            fakeUpstream,
            cache,
            activity,
            clientAccessPolicy: clientPolicy
        );

        byte[] query = DnsWire.BuildQuery("ads.example.com", DnsType.A, 0x1111);

        // Client 192.168.1.100 (Default group) -> Blocked
        var ansDefault = await server.HandleAsync(query, new IPEndPoint(IPAddress.Parse("192.168.1.100"), 50000), tcp: false, CancellationToken.None);
        Assert.NotNull(ansDefault);
        var ipsDefault = DnsWire.AddressAnswers(ansDefault);
        Assert.Equal(IPAddress.Any, ipsDefault[0]); // 0.0.0.0

        // Client 192.168.1.50 (ExemptDevice) -> Allowed (forwarded upstream)
        var ansExempt = await server.HandleAsync(query, new IPEndPoint(IPAddress.Parse("192.168.1.50"), 50000), tcp: false, CancellationToken.None);
        Assert.NotNull(ansExempt);
        var ipsExempt = DnsWire.AddressAnswers(ansExempt);
        Assert.Equal(IPAddress.Parse("1.2.3.4"), ipsExempt[0]);
    }

    [Fact]
    public async Task ClientGroups_SupportsGroupSpecificRules()
    {
        var baseFilter = DomainFilter.Empty;

        var settings = new DnsSettings
        {
            ClientGroups = new List<ClientGroup>
            {
                new()
                {
                    Name = "Kids",
                    ClientRanges = new List<string> { "192.168.1.0/28" },
                    CustomBlock = new List<string> { "social.example.com" }
                }
            }
        };

        var fakeUpstream = new FakeUpstream
        {
            Handler = (raw, _) => DnsWire.BuildResponse(
                DnsQuery.TryParse(raw, out var q, out string _) ? q! : null!,
                DnsRcode.NoError,
                new[] { (DnsType.A, new byte[] { 9, 9, 9, 9 }) }
            )
        };

        var cache = new DnsCache(100);
        var activity = new DnsActivity();
        var clientPolicy = new ClientAccessPolicy(restrictToLocal: false);

        using var server = new DnsServer(
            settings,
            () => baseFilter,
            fakeUpstream,
            cache,
            activity,
            clientAccessPolicy: clientPolicy
        );

        byte[] query = DnsWire.BuildQuery("social.example.com", DnsType.A, 0x2222);

        // Kid device in 192.168.1.0/28 subnet (e.g. 192.168.1.5) -> Blocked
        var ansKid = await server.HandleAsync(query, new IPEndPoint(IPAddress.Parse("192.168.1.5"), 50000), tcp: false, CancellationToken.None);
        Assert.NotNull(ansKid);
        Assert.Equal(IPAddress.Any, DnsWire.AddressAnswers(ansKid)[0]);

        // Adult device outside subnet (e.g. 192.168.1.50) -> Allowed
        var ansAdult = await server.HandleAsync(query, new IPEndPoint(IPAddress.Parse("192.168.1.50"), 50000), tcp: false, CancellationToken.None);
        Assert.NotNull(ansAdult);
        Assert.Equal(IPAddress.Parse("9.9.9.9"), DnsWire.AddressAnswers(ansAdult)[0]);
    }
}
