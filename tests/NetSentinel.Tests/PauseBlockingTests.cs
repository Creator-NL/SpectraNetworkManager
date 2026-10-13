using System.Net;
using NetSentinel.Sinkhole;
using Xunit;

namespace NetSentinel.Tests;

public class PauseBlockingTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _settingsFile;
    private readonly string _listsDir;

    public PauseBlockingTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "netsentinel-pause-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _settingsFile = Path.Combine(_tempDir, "dns-settings.json");
        _listsDir = Path.Combine(_tempDir, "lists");
        Directory.CreateDirectory(_listsDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public void PauseAndResume_TogglesStateAndClearsCache()
    {
        using var service = new DnsService(_settingsFile, _listsDir);

        bool? lastPauseEvent = null;
        service.BlockingPauseChanged += paused => lastPauseEvent = paused;

        Assert.False(service.IsBlockingPaused);
        Assert.Null(service.BlockingPausedUntil);

        // Put an item in cache
        var queryRaw = DnsWire.BuildQuery("test.com", DnsType.A, 1);
        Assert.True(DnsQuery.TryParse(queryRaw, out var query, out string _));
        var resp = DnsWire.BuildResponse(query!, DnsRcode.NoError, new[] { (DnsType.A, new byte[] { 1, 2, 3, 4 }) });

        service.Cache.Put("test", resp, DateTimeOffset.Now);
        Assert.Equal(1, service.Cache.Count);

        // Pause for 10 minutes
        service.PauseBlocking(TimeSpan.FromMinutes(10));

        Assert.True(service.IsBlockingPaused);
        Assert.NotNull(service.BlockingPausedUntil);
        Assert.True(service.BlockingPauseRemaining > TimeSpan.FromMinutes(9));
        Assert.True(lastPauseEvent);
        Assert.Equal(0, service.Cache.Count); // Cache cleared

        // Resume
        service.Cache.Put("test2", resp, DateTimeOffset.Now);
        Assert.Equal(1, service.Cache.Count);
        service.ResumeBlocking();

        Assert.False(service.IsBlockingPaused);
        Assert.Null(service.BlockingPausedUntil);
        Assert.False(lastPauseEvent);
        Assert.Equal(0, service.Cache.Count); // Cache cleared on resume
    }

    [Fact]
    public async Task HandleAsync_WhenPaused_AllowsBlockedDomains()
    {
        var settings = new DnsSettings
        {
            CustomBlock = new() { "ads.tracker.com" },
        };
        var filterBuilder = new DomainFilterBuilder();
        filterBuilder.AddBlock("ads.tracker.com");
        var filter = filterBuilder.Build();

        var upstream = new FakeUpstream();
        var cache = new DnsCache(100);
        var activity = new DnsActivity();

        bool isPaused = false;
        using var server = new DnsServer(settings, () => filter, upstream, cache, activity, isBlockingPaused: () => isPaused);

        byte[] rawQuery = DnsWire.BuildQuery("ads.tracker.com", DnsType.A, 0x1111);
        var clientEp = new IPEndPoint(IPAddress.Loopback, 12345);

        // 1. Normally blocked -> 0.0.0.0
        byte[]? blockedAnswer = await server.HandleAsync(rawQuery, clientEp, tcp: false, CancellationToken.None);
        Assert.NotNull(blockedAnswer);
        var blockedAddrs = DnsWire.AddressAnswers(blockedAnswer);
        Assert.Contains(IPAddress.Any, blockedAddrs);

        // 2. Pause blocking -> returns upstream resolution
        isPaused = true;
        upstream.Handler = (q, isTcp) =>
        {
            if (DnsQuery.TryParse(q, out var query, out string err) && query is not null)
            {
                return DnsWire.BuildResponse(query, DnsRcode.NoError, new[]
                {
                    (DnsType.A, IPAddress.Parse("93.184.216.34").GetAddressBytes())
                });
            }
            return null;
        };

        byte[]? allowedAnswer = await server.HandleAsync(rawQuery, clientEp, tcp: false, CancellationToken.None);
        Assert.NotNull(allowedAnswer);
        var allowedAddrs = DnsWire.AddressAnswers(allowedAnswer);
        Assert.Contains(IPAddress.Parse("93.184.216.34"), allowedAddrs);

        // 3. Resume blocking -> re-blocked
        isPaused = false;
        cache.Clear(); // ensure fresh lookup
        byte[]? reblockedAnswer = await server.HandleAsync(rawQuery, clientEp, tcp: false, CancellationToken.None);
        Assert.NotNull(reblockedAnswer);
        var reblockedAddrs = DnsWire.AddressAnswers(reblockedAnswer);
        Assert.Contains(IPAddress.Any, reblockedAddrs);
    }
}
