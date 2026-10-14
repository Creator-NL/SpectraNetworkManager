using SpectraNetworkManager.Core;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Tests;

public class StoreTests : IDisposable
{
    private readonly string _testDir;

    public StoreTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "SpectraNetworkManagerStoreTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_testDir, recursive: true); } catch { }
    }

    [Fact]
    public void RuleStore_SaveAndLoad_RoundTrips()
    {
        string file = Path.Combine(_testDir, "rules.json");
        var store1 = new RuleStore(file);
        store1.Set(new ProgramRule(@"C:\test\app.exe", RuleAction.Block, DateTimeOffset.UtcNow, null, RuleDirection.Outbound, TrafficScope.All));
        store1.TrustPublisher("Microsoft Corporation");

        var store2 = new RuleStore(file);
        var rule = store2.Find(@"C:\test\app.exe");
        Assert.NotNull(rule);
        Assert.Equal(RuleAction.Block, rule.Action);
        Assert.Equal(RuleDirection.Outbound, rule.Direction);
        Assert.True(store2.IsTrustedPublisher("Microsoft Corporation"));
        Assert.False(store2.IsTrustedPublisher("Unknown Publisher"));
    }

    [Fact]
    public void RuleStore_CorruptFile_RenamedToBadAndResetsToDefault()
    {
        string file = Path.Combine(_testDir, "rules.json");
        File.WriteAllText(file, "{ this is not valid json !!! }");

        var store = new RuleStore(file);
        Assert.Empty(store.All);
        Assert.Empty(store.TrustedPublishers);

        Assert.True(File.Exists(file + ".bad"));
    }

    [Fact]
    public void StrictModeStore_SaveAndLoad_RoundTrips()
    {
        string file = Path.Combine(_testDir, "strict-mode.json");
        var store1 = new StrictModeStore(file);
        var deadline = DateTimeOffset.UtcNow.AddMinutes(1);
        store1.Save(new StrictModeState(StrictPhase.Pending, deadline, new ProfileDefaults(1, 1, 1)));

        var store2 = new StrictModeStore(file);
        Assert.Equal(StrictPhase.Pending, store2.State.Phase);
        Assert.NotNull(store2.State.Previous);
        Assert.Equal(1, store2.State.Previous.Domain);
    }

    [Fact]
    public void StrictModeStore_CorruptFile_SetsWasUnreadableAndReturnsOff()
    {
        string file = Path.Combine(_testDir, "strict-mode.json");
        File.WriteAllText(file, "<<CORRUPT>>");

        var store = new StrictModeStore(file);
        Assert.Equal(StrictPhase.Off, store.State.Phase);
        Assert.True(store.WasUnreadable);
        Assert.True(File.Exists(file + ".bad"));
    }

    [Fact]
    public void SignatureCache_SaveAndLoad_RoundTrips()
    {
        string file = Path.Combine(_testDir, "sig-cache.json");
        var cache1 = new SignatureCache(file);
        var now = DateTimeOffset.UtcNow;
        var info = new SignatureInfo(SignatureStatus.Valid, "Valid Publisher", false, "Test summary");
        cache1.Put(@"C:\app.exe", 1024, 55555, now, info);
        cache1.Save();

        var cache2 = new SignatureCache(file);
        var retrieved = cache2.TryGet(@"C:\app.exe", 1024, 55555, now.AddMinutes(5));
        Assert.NotNull(retrieved);
        Assert.Equal(SignatureStatus.Valid, retrieved.Status);
        Assert.Equal("Valid Publisher", retrieved.Publisher);

        // Different length or timestamp -> cache miss
        Assert.Null(cache2.TryGet(@"C:\app.exe", 9999, 55555, now));
    }

    [Fact]
    public void DnsSettingsStore_SaveAndLoad_RoundTrips()
    {
        string file = Path.Combine(_testDir, "dns-settings.json");
        var store1 = new DnsSettingsStore(file);
        var settings = new DnsSettings
        {
            ListenAddress = "127.0.0.1",
            Port = 5353,
            BlockMode = BlockMode.NxDomain,
            Upstreams = new List<string> { "9.9.9.9", "1.1.1.1:53" },
            CustomBlock = new List<string> { "bad.com" },
            CustomAllow = new List<string> { "good.com" }
        };
        store1.Save(settings);

        var store2 = new DnsSettingsStore(file);
        var loaded = store2.Load();
        Assert.Equal(5353, loaded.Port);
        Assert.Equal(BlockMode.NxDomain, loaded.BlockMode);
        Assert.Equal(2, loaded.Upstreams.Count);
        Assert.Contains("bad.com", loaded.CustomBlock);
        Assert.Contains("good.com", loaded.CustomAllow);
    }
}
