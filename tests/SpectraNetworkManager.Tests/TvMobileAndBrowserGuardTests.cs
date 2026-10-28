using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using SpectraNetworkManager.Core.BrowserGuard;
using SpectraNetworkManager.Core.Devices;
using SpectraNetworkManager.Sinkhole;
using Xunit;

namespace SpectraNetworkManager.Tests;

public class TvMobileAndBrowserGuardTests
{
    [Fact]
    public void TvTelemetryCatalog_ReturnsValidDomainsPerVendor()
    {
        var samsung = TvTelemetryCatalog.GetDomainsForVendor("Samsung");
        Assert.NotEmpty(samsung);
        Assert.Contains(samsung, d => d.Contains("samsungacr.com"));

        var lg = TvTelemetryCatalog.GetDomainsForVendor("LG Electronics (webOS)");
        Assert.NotEmpty(lg);
        Assert.Contains(lg, d => d.Contains("smartshare.lgtvsdp.com"));

        var all = TvTelemetryCatalog.GetAllSmartTvAcrDomains();
        Assert.True(all.Count >= 20);
        Assert.Equal(all.Count, all.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void MobileTelemetryCatalog_ReturnsAdAndAttributionSdkDomains()
    {
        var mobile = MobileTelemetryCatalog.GetAllMobileTrackingDomains();
        Assert.NotEmpty(mobile);
        Assert.Contains(mobile, d => d.Contains("adjust.com"));
        Assert.Contains(mobile, d => d.Contains("appsflyer.com"));
        Assert.Contains(mobile, d => d.Contains("unityads.unity3d.com"));
    }

    [Fact]
    public void TvMobileManager_AssignDeviceAndApplyPresets()
    {
        var settings = new DnsSettings();
        TvMobileManager.EnsureDefaultGroups(settings);

        Assert.Contains(settings.ClientGroups, g => g.Name == TvMobileManager.SmartTvsGroupName);
        Assert.Contains(settings.ClientGroups, g => g.Name == TvMobileManager.MobileDevicesGroupName);

        bool assigned = TvMobileManager.AssignDeviceToGroup(
            settings,
            "192.168.1.55",
            TvMobileManager.SmartTvsGroupName,
            vendorHint: "Samsung",
            applyAcrPreset: true);

        Assert.True(assigned);
        var tvGroup = settings.ClientGroups.First(g => g.Name == TvMobileManager.SmartTvsGroupName);
        Assert.Contains("192.168.1.55", tvGroup.ClientRanges);
        Assert.Contains(tvGroup.CustomBlock, d => d.Contains("samsungacr.com"));
    }

    [Fact]
    public void DeviceProtectionEvaluator_CorrectlyClassifiesStates()
    {
        var tvIp = IPAddress.Parse("192.168.1.55");
        var routerIp = IPAddress.Parse("192.168.1.1");

        // 1. Direct protected (recent query seen)
        var direct = DeviceProtectionEvaluator.Evaluate(
            tvIp,
            routerIp,
            lastSeenQueryUtc: DateTime.UtcNow.AddMinutes(-5),
            totalQueries: 42,
            blockedQueries: 10,
            detectedDohAttempt: false);

        Assert.Equal(ProtectionLevel.DirectProtected, direct.Level);
        Assert.True(direct.IsActive);
        Assert.Contains("🟢", direct.BadgeText);

        // 2. Gateway routed (no direct query, gateway present)
        var gw = DeviceProtectionEvaluator.Evaluate(
            tvIp,
            routerIp,
            lastSeenQueryUtc: null,
            totalQueries: 0,
            blockedQueries: 0,
            detectedDohAttempt: false);

        Assert.Equal(ProtectionLevel.GatewayRouted, gw.Level);
        Assert.False(gw.IsActive);
        Assert.Contains("🟡", gw.BadgeText);

        // 3. DoH bypass attempt
        var doh = DeviceProtectionEvaluator.Evaluate(
            tvIp,
            routerIp,
            lastSeenQueryUtc: DateTime.UtcNow,
            totalQueries: 5,
            blockedQueries: 0,
            detectedDohAttempt: true);

        Assert.Equal(ProtectionLevel.DohBypassRisk, doh.Level);
        Assert.Contains("⚠️", doh.BadgeText);
    }

    [Fact]
    public void QrCodeSvgRenderer_GeneratesValidSvgAndMatrix()
    {
        string payload = "http://192.168.1.100:8765/?token=123456";
        string svg = QrCodeSvgRenderer.GenerateSvg(payload);

        Assert.NotEmpty(svg);
        Assert.Contains("<svg", svg);
        Assert.Contains("</svg>", svg);
        Assert.Contains("<rect", svg);

        var (matrix, size, margin) = QrCodeSvgRenderer.GenerateMatrix(payload);
        Assert.True(size >= 21);
        Assert.Equal(2, margin);
        // Finder pattern at top-left should have dark modules
        Assert.True(matrix[0, 0]);
        Assert.True(matrix[6, 6]);
    }

    [Fact]
    public void BrowserGuardManager_CreatesDefaultRulesAndExportsValidMv3Json()
    {
        string tempConfig = Path.Combine(Path.GetTempPath(), $"bg-test-{Guid.NewGuid():N}.json");
        try
        {
            var mgr = new BrowserGuardManager(tempConfig);
            Assert.NotEmpty(mgr.Config.CustomRules);

            // Check built-in YouTube Shorts rule
            var shorts = mgr.Config.CustomRules.FirstOrDefault(r => r.Id == "yt-shorts");
            Assert.NotNull(shorts);
            Assert.True(shorts.Enabled);
            Assert.Contains("youtube.com/shorts", shorts.Pattern);

            // Add custom rule
            mgr.AddRule("Block Custom Site", "*://*.badvideo.com/*", "Test", GuardAction.Block, "media");
            Assert.Contains(mgr.Config.CustomRules, r => r.Pattern == "*://*.badvideo.com/*");

            // Export to MV3 declarativeNetRequest JSON
            string json = mgr.ExportMv3DynamicRulesJson();
            Assert.NotEmpty(json);

            using var doc = JsonDocument.Parse(json);
            Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
            Assert.True(doc.RootElement.GetArrayLength() >= 2);

            var firstRule = doc.RootElement[0];
            Assert.True(firstRule.TryGetProperty("id", out _));
            Assert.True(firstRule.TryGetProperty("action", out var actionProp));
            Assert.Equal("block", actionProp.GetProperty("type").GetString());
            Assert.True(firstRule.TryGetProperty("condition", out var condProp));
            Assert.True(condProp.TryGetProperty("urlFilter", out _));
        }
        finally
        {
            if (File.Exists(tempConfig)) File.Delete(tempConfig);
        }
    }

    [Fact]
    public void LanProtectionPlanner_EnablesAndDisablesCorrectly()
    {
        var settings = new DnsSettings { ListenAddress = "127.0.0.1", RestrictClientsToLocalNetwork = false };
        LanProtectionPlanner.ApplyEnabled(settings);
        Assert.Equal("0.0.0.0", settings.ListenAddress);
        Assert.True(settings.RestrictClientsToLocalNetwork);

        LanProtectionPlanner.ApplyDisabled(settings);
        Assert.Equal("127.0.0.1", settings.ListenAddress);
    }

    [Fact]
    public void LanProtectionEvaluator_ReportsStatesAccurately()
    {
        // 1. Stopped
        var stopped = LanProtectionEvaluator.Evaluate(null, false, false, null, "192.168.1.10");
        Assert.Equal(LanProtectionLevel.Off, stopped.Level);

        // 2. Localhost only
        var local = LanProtectionEvaluator.Evaluate(new IPEndPoint(IPAddress.Loopback, 53), true, true, null, "192.168.1.10");
        Assert.Equal(LanProtectionLevel.Off, local.Level);

        // 3. Partial (firewall missing)
        var partial = LanProtectionEvaluator.Evaluate(new IPEndPoint(IPAddress.Any, 53), false, true, null, "192.168.1.10");
        Assert.Equal(LanProtectionLevel.Partial, partial.Level);

        // 4. Active with Public network warning
        var nets = new[] { new NetworkProfileInfo("Ethernet", NetworkCategoryKind.Public) };
        var active = LanProtectionEvaluator.Evaluate(new IPEndPoint(IPAddress.Any, 53), true, true, nets, "192.168.1.10");
        Assert.Equal(LanProtectionLevel.Active, active.Level);
        Assert.Contains(active.Warnings, w => w.Contains("Public"));
    }

    [Fact]
    public void DnsClientMatch_MatchesExactAndPort()
    {
        Assert.True(DnsClientMatch.IsSameClient("192.168.1.55", "192.168.1.55"));
        Assert.True(DnsClientMatch.IsSameClient("192.168.1.55:5353", "192.168.1.55"));
        Assert.False(DnsClientMatch.IsSameClient("192.168.1.5", "192.168.1.55"));
        Assert.False(DnsClientMatch.IsSameClient(null, "192.168.1.55"));
        Assert.False(DnsClientMatch.IsSameClient("192.168.1.55", null));
    }

    [Fact]
    public void OncePerRunGate_PassesOnceOnly()
    {
        var gate = new OncePerRunGate();
        Assert.True(gate.TryPass());
        Assert.False(gate.TryPass());
        Assert.False(gate.TryPass());
    }

    [Fact]
    public void ItemSyncPlanner_PlansAddAndRemovePreservingProtectedKey()
    {
        var current = new[] { 100, 200, 300 };
        var live = new[] { 200, 400 };
        int protectedKey = 100; // PID 100 is dead in live, but is protected because it's selected

        var (add, remove) = ItemSyncPlanner.Plan(current, live, protectedKey);

        Assert.Equal(new[] { 400 }, add);
        Assert.Equal(new[] { 300 }, remove); // 100 is NOT removed because it is protected
    }
}
