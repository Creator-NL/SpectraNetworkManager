using System.Net;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Tests;

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

    [Fact]
    public async Task ClientGroups_DynamicallyUpdatesWhenFilterChangesWithoutServerRestart()
    {
        var currentFilter = DomainFilter.Empty;

        var settings = new DnsSettings();

        var fakeUpstream = new FakeUpstream
        {
            Handler = (raw, _) => DnsWire.BuildResponse(
                DnsQuery.TryParse(raw, out var q, out string _) ? q! : null!,
                DnsRcode.NoError,
                new[] { (DnsType.A, new byte[] { 142, 251, 142, 206 }) }
            )
        };

        var cache = new DnsCache(100);
        var activity = new DnsActivity();

        using var server = new DnsServer(
            settings,
            () => currentFilter,
            fakeUpstream,
            cache,
            activity,
            clientAccessPolicy: new ClientAccessPolicy(restrictToLocal: false)
        );

        byte[] query = DnsWire.BuildQuery("doubleclick.net", DnsType.A, 0x3333);
        var clientEp = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 50000);

        // 1. Initially filter is empty -> query should be allowed & resolved upstream
        var ansBefore = await server.HandleAsync(query, clientEp, tcp: false, CancellationToken.None);
        Assert.NotNull(ansBefore);
        var ipsBefore = DnsWire.AddressAnswers(ansBefore);
        Assert.Equal(IPAddress.Parse("142.251.142.206"), ipsBefore[0]);

        // 2. Now simulate updating block lists in background while server keeps running
        var builder = new DomainFilterBuilder();
        builder.AddBlock("doubleclick.net");
        currentFilter = builder.Build();
        cache.Clear(); // Just like DnsService.UpdateListsAsync does

        // 3. Query again WITHOUT restarting DnsServer -> MUST be blocked (0.0.0.0)
        var ansAfter = await server.HandleAsync(query, clientEp, tcp: false, CancellationToken.None);
        Assert.NotNull(ansAfter);
        var ipsAfter = DnsWire.AddressAnswers(ansAfter);
        Assert.Equal(IPAddress.Any, ipsAfter[0]); // 0.0.0.0
    }
}
