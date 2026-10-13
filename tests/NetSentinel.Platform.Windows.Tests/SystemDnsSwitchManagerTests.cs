using NetSentinel.Platform.Windows;
using NetSentinel.Sinkhole;
using Xunit;

namespace NetSentinel.Tests;

public class SystemDnsSwitchManagerTests : IDisposable
{
    private sealed class FakeDnsSwitch : ISystemDnsSwitch
    {
        public List<NetworkAdapterDnsInfo> Adapters { get; } = new();
        public int AppliedCount { get; private set; }
        public int RestoredCount { get; private set; }
        public bool ShouldThrowOnApply { get; set; }

        public Task<IReadOnlyList<NetworkAdapterDnsInfo>> GetAdaptersAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<NetworkAdapterDnsInfo>>(Adapters);

        public Task ApplyDnsAsync(IEnumerable<int> interfaceIndexes, bool onlyLocal, IReadOnlyList<AdapterDnsBackup> backups, CancellationToken ct = default)
        {
            if (ShouldThrowOnApply) throw new InvalidOperationException("Simulated apply failure");
            AppliedCount++;
            return Task.CompletedTask;
        }

        public Task RestoreDnsAsync(IReadOnlyList<AdapterDnsBackup> backups, CancellationToken ct = default)
        {
            RestoredCount++;
            return Task.CompletedTask;
        }
    }

    private readonly string _tempDir;
    private readonly string _stateFile;
    private readonly string _backupFile;
    private readonly FakeDnsSwitch _fakeSwitch = new();

    public SystemDnsSwitchManagerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "netsentinel-dnsmgr-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _stateFile = Path.Combine(_tempDir, "dns-switch.json");
        _backupFile = Path.Combine(_tempDir, "dns-backup.json");

        _fakeSwitch.Adapters.Add(new NetworkAdapterDnsInfo(
            13, "Ethernet", "Intel Gigabit", "{GUID-13}", "Up", false, false,
            new[] { "84.116.46.22", "84.116.46.23" }, true,
            new[] { "2001:b88::1" }, true));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public async Task StartupRecovery_WhenPendingStateExists_RevertsToOriginalDns()
    {
        var store = new SystemDnsSwitchStore(_stateFile, _backupFile);
        var backups = new List<AdapterDnsBackup>
        {
            new(13, "Ethernet", "{GUID-13}", new[] { "84.116.46.22" }, true, Array.Empty<string>(), true)
        };
        store.Save(new SystemDnsSwitchState(DnsSwitchPhase.Pending, DateTimeOffset.UtcNow.AddMinutes(1), false, backups));

        using var manager = new SystemDnsSwitchManager(store, _fakeSwitch);

        bool recovered = await manager.CheckStartupRecoveryAsync();

        Assert.True(recovered, "Startup recovery should detect pending state.");
        Assert.Equal(1, _fakeSwitch.RestoredCount);
        Assert.Equal(DnsSwitchPhase.Off, manager.State.Phase);
    }

    [Fact]
    public async Task ApplyAndConfirm_FlowTransitionsPendingToActive()
    {
        var store = new SystemDnsSwitchStore(_stateFile, _backupFile);
        using var manager = new SystemDnsSwitchManager(store, _fakeSwitch);

        Assert.False(manager.IsActive);
        Assert.False(manager.IsPending);

        await manager.ApplyAsync(new[] { 13 }, onlyLocal: false);

        Assert.True(manager.IsPending);
        Assert.False(manager.IsActive);
        Assert.Equal(1, _fakeSwitch.AppliedCount);
        Assert.Single(manager.State.Backups);

        // Confirm
        manager.Confirm();

        Assert.True(manager.IsActive);
        Assert.False(manager.IsPending);
        Assert.Equal(DnsSwitchPhase.Active, store.State.Phase);
    }

    [Fact]
    public async Task Revert_RestoresPreviousDnsAndSetsOff()
    {
        var store = new SystemDnsSwitchStore(_stateFile, _backupFile);
        using var manager = new SystemDnsSwitchManager(store, _fakeSwitch);

        await manager.ApplyAsync(new[] { 13 }, onlyLocal: false);
        manager.Confirm();

        Assert.True(manager.IsActive);

        // Revert (or Panic)
        await manager.RevertAsync();

        Assert.Equal(1, _fakeSwitch.RestoredCount);
        Assert.False(manager.IsActive);
        Assert.Equal(DnsSwitchPhase.Off, manager.State.Phase);
    }

    [Fact]
    public async Task Apply_WhenFails_AutomaticallyRollsBack()
    {
        _fakeSwitch.ShouldThrowOnApply = true;
        var store = new SystemDnsSwitchStore(_stateFile, _backupFile);
        using var manager = new SystemDnsSwitchManager(store, _fakeSwitch);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            manager.ApplyAsync(new[] { 13 }, onlyLocal: false));

        Assert.Equal(1, _fakeSwitch.RestoredCount);
        Assert.Equal(DnsSwitchPhase.Off, manager.State.Phase);
    }
}
