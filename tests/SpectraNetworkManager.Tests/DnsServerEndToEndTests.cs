using System.Net;
using System.Net.Sockets;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Tests;

public class DnsServerEndToEndTests : IDisposable
{
    private readonly FakeUpstream _fakeUpstream = new();
    private readonly DnsSettings _settings;
    private readonly DomainFilterBuilder _filterBuilder = new();
    private readonly DnsCache _cache;
    private readonly DnsActivity _activity;
    private DnsServer? _server;

    public DnsServerEndToEndTests()
    {
        _settings = new DnsSettings
        {
            ListenAddress = "127.0.0.1",
            Port = 0, // dynamic port picked by the OS
            InspectCnames = true,
            BlockBrowserDoh = true,
            BlockMode = BlockMode.NullAddress
        };
        _cache = new DnsCache(100);
        _activity = new DnsActivity();
    }

    public void Dispose()
    {
        _server?.Dispose();
    }

    private DnsServer StartServer()
    {
        var filter = _filterBuilder.Build();
        var server = new DnsServer(_settings, () => filter, _fakeUpstream, _cache, _activity);
        server.Start();
        _server = server;
        return server;
    }

    private static async Task<byte[]> QueryServerUdpAsync(IPEndPoint serverEndpoint, string domain, ushort type, ushort id = 1234)
    {
        using var client = new UdpClient();
        client.Connect(serverEndpoint);
        byte[] query = DnsWire.BuildQuery(domain, type, id);
        await client.SendAsync(query);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var result = await client.ReceiveAsync(cts.Token);
        return result.Buffer;
    }

    [Fact]
    public async Task BlockedQuery_ReturnsNullAnswer_UpstreamNeverCalled()
    {
        _filterBuilder.AddBlock("ads.example.com");
        var server = StartServer();

        byte[] resp = await QueryServerUdpAsync(server.LocalEndPoint!, "ads.example.com", DnsType.A);
        Assert.Equal(DnsRcode.NoError, DnsWire.ResponseRcode(resp));
        var addrs = DnsWire.AddressAnswers(resp);
        Assert.Single(addrs);
        Assert.Equal(IPAddress.Any, addrs[0]); // 0.0.0.0

        Assert.Equal(0, _fakeUpstream.CallCount);
    }

    [Fact]
    public async Task ForwardedQuery_CallsUpstreamOnce_ThenAnswersFromCache()
    {
        _fakeUpstream.Handler = (q, isTcp) =>
        {
            if (DnsQuery.TryParse(q, out var query, out var err) && query is not null)
            {
                return DnsWire.BuildResponse(query, DnsRcode.NoError, new[]
                {
                    (DnsType.A, new byte[] { 93, 184, 216, 34 })
                }, ttl: 300);
            }
            return null;
        };

        var server = StartServer();

        // 1st query: forwarded to upstream
        byte[] resp1 = await QueryServerUdpAsync(server.LocalEndPoint!, "example.com", DnsType.A, id: 100);
        Assert.Equal(DnsRcode.NoError, DnsWire.ResponseRcode(resp1));
        var addrs1 = DnsWire.AddressAnswers(resp1);
        Assert.Single(addrs1);
        Assert.Equal(IPAddress.Parse("93.184.216.34"), addrs1[0]);
        Assert.Equal(1, _fakeUpstream.CallCount);

        // 2nd query: served from cache
        byte[] resp2 = await QueryServerUdpAsync(server.LocalEndPoint!, "example.com", DnsType.A, id: 200);
        Assert.Equal(DnsRcode.NoError, DnsWire.ResponseRcode(resp2));
        var addrs2 = DnsWire.AddressAnswers(resp2);
        Assert.Single(addrs2);
        Assert.Equal(IPAddress.Parse("93.184.216.34"), addrs2[0]);
        Assert.Equal(1, _fakeUpstream.CallCount); // Still 1!
    }

    [Fact]
    public async Task FirefoxCanary_ReturnsNxDomain_UpstreamNeverCalled()
    {
        var server = StartServer();

        byte[] resp = await QueryServerUdpAsync(server.LocalEndPoint!, "use-application-dns.net", DnsType.A);
        Assert.Equal(DnsRcode.NxDomain, DnsWire.ResponseRcode(resp));
        Assert.Equal(0, _fakeUpstream.CallCount);
    }

    [Fact]
    public async Task UpstreamNull_ReturnsServFail()
    {
        _fakeUpstream.Handler = (_, _) => null;
        var server = StartServer();

        byte[] resp = await QueryServerUdpAsync(server.LocalEndPoint!, "unreachable.test", DnsType.A);
        Assert.Equal(DnsRcode.ServFail, DnsWire.ResponseRcode(resp));
        Assert.Equal(1, _fakeUpstream.CallCount);
    }

    [Fact]
    public async Task ParallelQueries_AllAnsweredCorrectly()
    {
        _fakeUpstream.Handler = (q, isTcp) =>
        {
            if (DnsQuery.TryParse(q, out var query, out var err) && query is not null)
            {
                return DnsWire.BuildResponse(query, DnsRcode.NoError, new[]
                {
                    (DnsType.A, new byte[] { 1, 1, 1, 1 })
                }, ttl: 60);
            }
            return null;
        };

        var server = StartServer();
        var tasks = Enumerable.Range(0, 50).Select(async i =>
        {
            byte[] resp = await QueryServerUdpAsync(server.LocalEndPoint!, $"host{i}.test", DnsType.A, id: (ushort)(i + 10));
            Assert.Equal(DnsRcode.NoError, DnsWire.ResponseRcode(resp));
        });

        await Task.WhenAll(tasks);
    }
}
