using NetSentinel.Sinkhole;
using Xunit;

namespace NetSentinel.Tests;

public class SystemDnsSwitchStoreTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _stateFile;
    private readonly string _backupFile;

    public SystemDnsSwitchStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "netsentinel-switchstore-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _stateFile = Path.Combine(_tempDir, "dns-switch.json");
        _backupFile = Path.Combine(_tempDir, "dns-backup.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public void Store_WhenFileDoesNotExist_ReturnsOff()
    {
        var store = new SystemDnsSwitchStore(_stateFile, _backupFile);

        Assert.Equal(DnsSwitchPhase.Off, store.State.Phase);
        Assert.False(store.WasUnreadable);
        Assert.Empty(store.State.Backups);
    }

    [Fact]
    public void Store_RoundtripsStateAndBackupsAtomically()
    {
        var store = new SystemDnsSwitchStore(_stateFile, _backupFile);

        var backups = new List<AdapterDnsBackup>
        {
            new(13, "Ethernet", "{GUID-1}", new[] { "84.116.46.22", "84.116.46.23" }, true, new[] { "2001:b88::1" }, false),
            new(17, "Wi-Fi", "{GUID-2}", new[] { "192.168.1.1" }, true, Array.Empty<string>(), true),
        };

        var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
        var pending = new SystemDnsSwitchState(DnsSwitchPhase.Pending, deadline, false, backups);

        store.Save(pending);

        Assert.True(File.Exists(_stateFile));
        Assert.True(File.Exists(_backupFile));

        // Reload fresh from disk
        var reloaded = new SystemDnsSwitchStore(_stateFile, _backupFile);
        Assert.Equal(DnsSwitchPhase.Pending, reloaded.State.Phase);
        Assert.Equal(2, reloaded.State.Backups.Count);
        Assert.Equal("Ethernet", reloaded.State.Backups[0].Name);
        Assert.True(reloaded.State.Backups[0].Ipv4IsDhcp);
        Assert.False(reloaded.State.Backups[0].Ipv6IsDhcp);

        // Verify standalone backup loader
        var loadedBackups = reloaded.LoadBackupFile();
        Assert.Equal(2, loadedBackups.Count);
        Assert.Equal("Wi-Fi", loadedBackups[1].Name);
    }

    [Fact]
    public void Store_WhenFileIsCorrupted_SetsAsideAsBadAndReturnsOff()
    {
        File.WriteAllText(_stateFile, "{ this is corrupted json }}}");

        var store = new SystemDnsSwitchStore(_stateFile, _backupFile);

        Assert.Equal(DnsSwitchPhase.Off, store.State.Phase);
        Assert.True(store.WasUnreadable);
        Assert.True(File.Exists(_stateFile + ".bad"));
    }
}
