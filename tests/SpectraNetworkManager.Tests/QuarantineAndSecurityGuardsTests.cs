using SpectraNetworkManager.Core;
using Xunit;

namespace SpectraNetworkManager.Tests;

public sealed class QuarantineVaultTests : IDisposable
{
    private readonly string _tempVaultFile;

    public QuarantineVaultTests()
    {
        _tempVaultFile = Path.Combine(Path.GetTempPath(), $"quarantine-vault-test-{Guid.NewGuid():N}.json");
    }

    public void Dispose()
    {
        try { if (File.Exists(_tempVaultFile)) File.Delete(_tempVaultFile); } catch { }
    }

    [Fact]
    public void QuarantineVault_PersistsAndRetrievesSnapshots()
    {
        var vault = new QuarantineVault(_tempVaultFile);

        var snap = new QuarantineSnapshot
        {
            ExecutablePath = @"C:\Malicious\SuspiciousTool.exe",
            ProgramName = "SuspiciousTool.exe",
            Reason = "User manual quarantine",
            QuarantinedAtUtc = DateTimeOffset.UtcNow,
            PreviousRuleAction = RuleAction.Allow,
            TerminatedPids = new List<int> { 1234, 5678 },
            ClosedSocketsCount = 4,
            ModifiedServices = new List<QuarantineServiceRecord>
            {
                new("SuspiciousSvc", "Suspicious Service", 2, true)
            },
            DisabledStartupEntries = new List<QuarantineStartupRecord>
            {
                new("HKCU\\Run\\SuspiciousTool", "SuspiciousTool", "Registry: HKCU Run")
            },
            FirewallRulesApplied = true
        };

        vault.SaveSnapshot(snap);

        var all = vault.GetAll();
        Assert.Single(all);
        Assert.Equal(@"C:\Malicious\SuspiciousTool.exe", all[0].ExecutablePath);
        Assert.False(all[0].IsRestored);
        Assert.Equal(2, all[0].TerminatedPids.Count);
        Assert.Equal(4, all[0].ClosedSocketsCount);
        Assert.Single(all[0].ModifiedServices);
        Assert.Single(all[0].DisabledStartupEntries);
        Assert.True(all[0].FirewallRulesApplied);

        var active = vault.FindByPath(@"C:\Malicious\SuspiciousTool.exe");
        Assert.NotNull(active);
        Assert.Equal(snap.Id, active.Id);

        // Mark restored
        vault.MarkRestored(snap.Id);
        Assert.Empty(vault.GetActive());
        var restored = vault.GetAll().First();
        Assert.True(restored.IsRestored);
        Assert.NotNull(restored.RestoredAtUtc);

        // Should no longer find active by path
        Assert.Null(vault.FindByPath(@"C:\Malicious\SuspiciousTool.exe"));
    }

    [Fact]
    public void DeviceClassifier_RecognizesBitaxeMinerOuisAndHostnames()
    {
        // 440176 OUI
        var dev1 = DeviceClassifier.Classify(
            "44-01-76-A4-A6-24",
            "");

        Assert.Equal(DeviceKind.IotOrSmartHome, dev1.Kind);
        Assert.Contains("Bitaxe", dev1.Vendor, StringComparison.OrdinalIgnoreCase);

        // 940100 OUI
        var dev2 = DeviceClassifier.Classify(
            "94-01-00-6B-E5-FC",
            "");

        Assert.Equal(DeviceKind.IotOrSmartHome, dev2.Kind);
        Assert.Contains("Bitaxe", dev2.Vendor, StringComparison.OrdinalIgnoreCase);

        // Hostname fallback
        var dev3 = DeviceClassifier.Classify(
            "00-11-22-33-44-55",
            "bitaxe-ultra-01");

        Assert.Equal(DeviceKind.IotOrSmartHome, dev3.Kind);
        Assert.Contains("Bitaxe", dev3.Description, StringComparison.OrdinalIgnoreCase);
    }
}
