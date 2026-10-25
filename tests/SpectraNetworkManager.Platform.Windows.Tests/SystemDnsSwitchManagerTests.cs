using SpectraNetworkManager.Platform.Windows;
using SpectraNetworkManager.Sinkhole;
using Xunit;

namespace SpectraNetworkManager.Tests;

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
        _tempDir = Path.Combine(Path.GetTempPath(), "spectranetworkmanager-dnsmgr-" + Guid.NewGuid().ToString("N"));
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

    [Theory]
    [InlineData("Ethernet", "Realtek PCIe GbE Family Controller", System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, false, true)]
    [InlineData("Ethernet 2", "Realtek Gaming 2.5GbE Family Controller", System.Net.NetworkInformation.NetworkInterfaceType.GigabitEthernet, true, true)]
    [InlineData("ASUS LAN", "Intel(R) Ethernet Controller I225-V", System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, false, true)]
    [InlineData("Killer", "Killer E3100G 2.5 Gigabit Ethernet Controller", System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, false, true)]
    public void ClassifyAdapter_PhysicalEthernetAndRealtekPcieGbe_AreNeverMarkedVirtualEvenWhenWmiSaysVirtual(
        string name,
        string description,
        System.Net.NetworkInformation.NetworkInterfaceType type,
        bool hasGateway,
        bool wmiReportedVirtual)
    {
        var (isNoise, isVirtual, isWireless, kind) = WindowsSystemDnsSwitch.ClassifyAdapter(
            name, description, type, hasGateway, wmiReportedVirtual);

        Assert.False(isNoise);
        Assert.False(isVirtual);
        Assert.False(isWireless);
        Assert.Equal("Ethernet", kind);
    }

    [Theory]
    [InlineData("Wi-Fi", "Intel(R) Wi-Fi 6E AX210 160MHz", System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211)]
    [InlineData("WLAN", "MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz Wireless LAN Card", System.Net.NetworkInformation.NetworkInterfaceType.Ethernet)]
    [InlineData("Wi-Fi", "Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC", System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211)]
    public void ClassifyAdapter_WirelessAdapters_AreDetectedAsWiFiAndNotVirtual(
        string name,
        string description,
        System.Net.NetworkInformation.NetworkInterfaceType type)
    {
        var (isNoise, isVirtual, isWireless, kind) = WindowsSystemDnsSwitch.ClassifyAdapter(
            name, description, type, hasDefaultGateway: true, wmiReportedVirtual: true);

        Assert.False(isNoise);
        Assert.False(isVirtual);
        Assert.True(isWireless);
        Assert.Equal("Wi-Fi", kind);
    }

    [Fact]
    public void ClassifyAdapter_VirtualSwitchWithDefaultGateway_IsNotHiddenAsVirtual()
    {
        var (isNoise, isVirtual, _, _) = WindowsSystemDnsSwitch.ClassifyAdapter(
            "vEthernet (Default Switch)",
            "Hyper-V Virtual Ethernet Adapter",
            System.Net.NetworkInformation.NetworkInterfaceType.Ethernet,
            hasDefaultGateway: true,
            wmiReportedVirtual: true);

        Assert.False(isNoise);
        Assert.False(isVirtual);
    }

    [Fact]
    public void ClassifyAdapter_VirtualSwitchWithoutGateway_IsMarkedVirtual()
    {
        var (isNoise, isVirtual, _, kind) = WindowsSystemDnsSwitch.ClassifyAdapter(
            "vEthernet (WSL)",
            "Hyper-V Virtual Ethernet Adapter",
            System.Net.NetworkInformation.NetworkInterfaceType.Ethernet,
            hasDefaultGateway: false,
            wmiReportedVirtual: true);

        Assert.False(isNoise);
        Assert.True(isVirtual);
        Assert.Equal("Virtual / VPN", kind);
    }

    [Fact]
    public void GetAdaptersNative_ReturnsAdaptersInProcessWithoutThrowing()
    {
        var adapters = WindowsSystemDnsSwitch.GetAdaptersNative();
        Assert.NotNull(adapters);
        foreach (var a in adapters)
        {
            Assert.True(a.InterfaceIndex > 0);
            Assert.False(string.IsNullOrWhiteSpace(a.Name));
            Assert.False(string.IsNullOrWhiteSpace(a.Description));
        }
    }
}
