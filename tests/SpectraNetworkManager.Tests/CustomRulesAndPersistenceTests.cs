using System.Net;
using SpectraNetworkManager.Sinkhole;
using Xunit;

namespace SpectraNetworkManager.Tests;

public sealed class CustomRulesAndPersistenceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _settingsPath;
    private readonly string _listsFolder;

    public CustomRulesAndPersistenceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "Spectra_CustomRules_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _settingsPath = Path.Combine(_tempDir, "dns-settings.json");
        _listsFolder = Path.Combine(_tempDir, "blocklists");
        Directory.CreateDirectory(_listsFolder);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public async Task DnsService_CustomBlock_CanBeRemovedAndUndone()
    {
        using var dns = new DnsService(_settingsPath, _listsFolder);

        // Initially not custom blocked
        Assert.False(dns.IsCustomBlocked("push.services.mozilla.com"));

        // User blocks domain
        await dns.BlockDomainAsync("push.services.mozilla.com");
        Assert.True(dns.IsCustomBlocked("push.services.mozilla.com"));
        Assert.False(dns.IsCustomAllowed("push.services.mozilla.com"));
        Assert.Equal(FilterAction.Blocked, dns.Decide("push.services.mozilla.com").Action);

        // User removes the custom rule (undoes misclick)
        await dns.RemoveCustomRuleAsync("push.services.mozilla.com");
        Assert.False(dns.IsCustomBlocked("push.services.mozilla.com"));
        Assert.False(dns.IsCustomAllowed("push.services.mozilla.com"));
    }

    [Fact]
    public async Task DnsService_CustomAllow_CanBeRemovedAndUndone()
    {
        using var dns = new DnsService(_settingsPath, _listsFolder);

        await dns.AllowDomainAsync("my-safe-site.com");
        Assert.True(dns.IsCustomAllowed("my-safe-site.com"));
        Assert.False(dns.IsCustomBlocked("my-safe-site.com"));

        await dns.RemoveCustomRuleAsync("my-safe-site.com");
        Assert.False(dns.IsCustomAllowed("my-safe-site.com"));
    }

    [Fact]
    public void DnsService_PreloadsCachedFilter_OnConstruction()
    {
        // Write a mock blocklist file into lists folder
        var list = new BlocklistSource("MockList", "https://example.com/mock-list.txt", true);
        string filename = "MockList-" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(list.Url.ToLowerInvariant())), 0, 4).ToLowerInvariant() + ".txt";
        File.WriteAllLines(Path.Combine(_listsFolder, filename), new[] { "0.0.0.0 bad-domain.net", "0.0.0.0 tracker.com" });

        var settings = new DnsSettings
        {
            Lists = new List<BlocklistSource> { list }
        };
        new DnsSettingsStore(_settingsPath).Save(settings);

        // Initialize DnsService - it should immediately reload filter without needing StartAsync
        using var dns = new DnsService(_settingsPath, _listsFolder);
        Assert.Equal(2, dns.BlockedDomainCount);
        Assert.Equal(FilterAction.Blocked, dns.Decide("bad-domain.net").Action);
        Assert.Equal(FilterAction.Blocked, dns.Decide("tracker.com").Action);
    }
}
