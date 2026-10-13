using System.Net;
using NetSentinel.Sinkhole;

namespace NetSentinel.Tests;

public sealed class LocalRecordsAndForwardingTests
{
    [Fact]
    public async Task DnsServer_AnswersLoopbackPtrLocally()
    {
        var settings = new DnsSettings();
        var fakeUpstream = new FakeUpstream();
        var cache = new DnsCache(100);
        var activity = new DnsActivity();
        var clientPolicy = new ClientAccessPolicy(restrictToLocal: false);

        using var server = new DnsServer(
            settings,
            () => DomainFilter.Empty,
            fakeUpstream,
            cache,
            activity,
            clientAccessPolicy: clientPolicy
        );

        byte[] query = DnsWire.BuildQuery("1.0.0.127.in-addr.arpa", DnsType.PTR, 0x1234);
        var answer = await server.HandleAsync(query, new IPEndPoint(IPAddress.Loopback, 54321), tcp: false, CancellationToken.None);

        Assert.NotNull(answer);
        Assert.Equal(0, fakeUpstream.CallCount); // Upstream was NOT called

        int pos = UnsafePos(answer);
        Assert.True(DnsWire.TryReadName(answer, ref pos, out string ptrTarget));
        Assert.Equal("localhost", ptrTarget);
    }

    [Fact]
    public async Task DnsServer_AnswersLocalRecordsDirectly()
    {
        var settings = new DnsSettings
        {
            LocalRecords = new List<LocalDnsRecord>
            {
                new("nas.home", "A", "192.168.1.100", 300),
                new("storage.home", "CNAME", "nas.home", 300),
                new("100.1.168.192.in-addr.arpa", "PTR", "nas.home", 300)
            }
        };

        var fakeUpstream = new FakeUpstream();
        var cache = new DnsCache(100);
        var activity = new DnsActivity();
        var clientPolicy = new ClientAccessPolicy(restrictToLocal: false);

        using var server = new DnsServer(
            settings,
            () => DomainFilter.Empty,
            fakeUpstream,
            cache,
            activity,
            clientAccessPolicy: clientPolicy
        );

        // 1. Query A for nas.home
        byte[] qA = DnsWire.BuildQuery("nas.home", DnsType.A, 0x1111);
        var ansA = await server.HandleAsync(qA, new IPEndPoint(IPAddress.Loopback, 54321), tcp: false, CancellationToken.None);
        Assert.NotNull(ansA);
        Assert.Equal(0, fakeUpstream.CallCount);
        var ips = DnsWire.AddressAnswers(ansA);
        Assert.Single(ips);
        Assert.Equal(IPAddress.Parse("192.168.1.100"), ips[0]);

        // 2. Query CNAME for storage.home
        byte[] qCname = DnsWire.BuildQuery("storage.home", DnsType.CNAME, 0x2222);
        var ansCname = await server.HandleAsync(qCname, new IPEndPoint(IPAddress.Loopback, 54321), tcp: false, CancellationToken.None);
        Assert.NotNull(ansCname);
        Assert.Equal(0, fakeUpstream.CallCount);
        var targets = DnsWire.CnameTargets(ansCname);
        Assert.Single(targets);
        Assert.Equal("nas.home", targets[0]);

        // 3. Query AAAA for nas.home (which only has A record) -> NOERROR NODATA
        byte[] qAaaa = DnsWire.BuildQuery("nas.home", DnsType.AAAA, 0x3333);
        var ansAaaa = await server.HandleAsync(qAaaa, new IPEndPoint(IPAddress.Loopback, 54321), tcp: false, CancellationToken.None);
        Assert.NotNull(ansAaaa);
        Assert.Equal(0, fakeUpstream.CallCount);
        Assert.Equal(DnsRcode.NoError, DnsWire.ResponseRcode(ansAaaa));
        Assert.Empty(DnsWire.AddressAnswers(ansAaaa));
    }

    [Fact]
    public async Task DnsServer_RoutesConditionalForwardingToDesignatedTarget()
    {
        var settings = new DnsSettings();
        var fakeGeneralUpstream = new FakeUpstream();
        var fakeRouterUpstream = new FakeUpstream
        {
            Handler = (raw, _) => DnsWire.BuildResponse(
                DnsQuery.TryParse(raw, out var q, out string _) ? q! : null!,
                DnsRcode.NoError,
                new[] { (DnsType.A, new byte[] { 10, 0, 0, 50 }) }
            )
        };

        var cache = new DnsCache(100);
        var activity = new DnsActivity();
        var clientPolicy = new ClientAccessPolicy(restrictToLocal: false);

        using var condFwd = new ConditionalForwarder(new[] { ("lan", (IUpstreamResolver)fakeRouterUpstream) });
        using var server = new DnsServer(
            settings,
            () => DomainFilter.Empty,
            fakeGeneralUpstream,
            cache,
            activity,
            clientAccessPolicy: clientPolicy,
            conditionalForwarder: condFwd
        );

        // When device.lan is queried -> handled by router upstream
        byte[] qLan = DnsWire.BuildQuery("device.lan", DnsType.A, 0x4444);
        var ansLan = await server.HandleAsync(qLan, new IPEndPoint(IPAddress.Loopback, 54321), tcp: false, CancellationToken.None);
        Assert.NotNull(ansLan);
        Assert.Equal(1, fakeRouterUpstream.CallCount);
        Assert.Equal(0, fakeGeneralUpstream.CallCount);
        var ips = DnsWire.AddressAnswers(ansLan);
        Assert.Equal(IPAddress.Parse("10.0.0.50"), ips[0]);

        // When external.com is queried -> handled by general upstream
        byte[] qExt = DnsWire.BuildQuery("external.com", DnsType.A, 0x5555);
        fakeGeneralUpstream.Handler = (raw, _) => DnsWire.BuildResponse(
            DnsQuery.TryParse(raw, out var q, out string _) ? q! : null!,
            DnsRcode.NoError,
            new[] { (DnsType.A, new byte[] { 93, 184, 216, 34 }) }
        );
        var ansExt = await server.HandleAsync(qExt, new IPEndPoint(IPAddress.Loopback, 54321), tcp: false, CancellationToken.None);
        Assert.NotNull(ansExt);
        Assert.Equal(1, fakeGeneralUpstream.CallCount);
    }

    private static int UnsafePos(byte[] answer)
    {
        int pos = 12;
        DnsWire.TrySkipName(answer, ref pos);
        pos += 4; // type + class
        pos += 12; // name (2) + type (2) + class (2) + ttl (4) + rdlen (2)
        return pos;
    }
}
