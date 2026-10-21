using SpectraNetworkManager.Sinkhole;
using Xunit;

namespace SpectraNetworkManager.Tests;

public class DomainIntelligenceTests
{
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("www.example.com", "example.com")]
    [InlineData("sub.tracker.doubleclick.net", "doubleclick.net")]
    [InlineData("news.bbc.co.uk", "bbc.co.uk")]
    [InlineData("adserver.sydney.com.au", "sydney.com.au")]
    [InlineData("tokyo.ne.jp", "tokyo.ne.jp")]
    public void GetRootDomain_ExtractsCorrectRoot(string domain, string expectedRoot)
    {
        string root = DomainIntelligence.GetRootDomain(domain);
        Assert.Equal(expectedRoot, root);
    }

    [Fact]
    public void Analyze_GoogleAdsAndDoubleClick_ClassifiedAsSafeToBlock()
    {
        var analysis = DomainIntelligence.Analyze("pagead2.googlesyndication.com");
        Assert.Equal(DomainCategory.AdvertisingTracker, analysis.Category);
        Assert.Equal(BlockAdvice.SafeToBlock, analysis.Advice);
        Assert.Contains("Google", analysis.ServiceName);

        var dcAnalysis = DomainIntelligence.Analyze("ad.doubleclick.net");
        Assert.Equal(DomainCategory.AdvertisingTracker, dcAnalysis.Category);
        Assert.Equal(BlockAdvice.SafeToBlock, dcAnalysis.Advice);
    }

    [Fact]
    public void Analyze_YouTubeGoogleVideo_ClassifiedAsCautionDoNotBlock()
    {
        var analysis = DomainIntelligence.Analyze("r1---sn-4g5edn6e.googlevideo.com");
        Assert.Equal(DomainCategory.StreamingMedia, analysis.Category);
        Assert.Equal(BlockAdvice.CautionBreakagePossible, analysis.Advice);
        Assert.Contains("YouTube", analysis.ServiceName);
    }

    [Fact]
    public void Analyze_MicrosoftMsnTelemetry_ClassifiedAsSafeToBlock()
    {
        var analysis = DomainIntelligence.Analyze("data.msn.com");
        Assert.Equal(DomainCategory.TelemetryAnalytics, analysis.Category);
        Assert.Equal(BlockAdvice.SafeToBlock, analysis.Advice);
        Assert.Contains("Microsoft", analysis.ServiceName);

        var telemetryAnalysis = DomainIntelligence.Analyze("telemetry.microsoft.com");
        Assert.Equal(DomainCategory.TelemetryAnalytics, telemetryAnalysis.Category);
        Assert.Equal(BlockAdvice.SafeToBlock, telemetryAnalysis.Advice);
    }

    [Fact]
    public void Analyze_AdExchanges_ClassifiedAsSafeToBlock()
    {
        foreach (var domain in new[] { "static.criteo.com", "ib.adnxs.com", "trc.taboola.com", "outbrain.com", "pubmatic.com" })
        {
            var analysis = DomainIntelligence.Analyze(domain);
            Assert.Equal(DomainCategory.AdvertisingTracker, analysis.Category);
            Assert.Equal(BlockAdvice.SafeToBlock, analysis.Advice);
        }
    }

    [Fact]
    public void Analyze_CloudflareAndAkamaiCdn_ClassifiedAsEssential()
    {
        var cfAnalysis = DomainIntelligence.Analyze("cdnjs.cloudflare.com");
        Assert.Equal(DomainCategory.CdnInfrastructure, cfAnalysis.Category);
        Assert.Equal(BlockAdvice.EssentialKeepAllowed, cfAnalysis.Advice);

        var akamaiAnalysis = DomainIntelligence.Analyze("a248.e.akamai.net");
        Assert.Equal(DomainCategory.CdnInfrastructure, akamaiAnalysis.Category);
        Assert.Equal(BlockAdvice.EssentialKeepAllowed, akamaiAnalysis.Advice);
    }

    [Fact]
    public void Analyze_BlockedDomain_ReflectsCurrentlyBlocked()
    {
        var analysis = DomainIntelligence.Analyze("some-tracking-host.org", isBlocked: true);
        Assert.Equal(BlockAdvice.CurrentlyBlocked, analysis.Advice);
        Assert.Contains("Blocked", analysis.AdviceTitle);
    }

    [Fact]
    public void Analyze_HeuristicAdKeyword_ClassifiedAsAdTracker()
    {
        var analysis = DomainIntelligence.Analyze("tracker.unknown-startup.io");
        Assert.Equal(DomainCategory.AdvertisingTracker, analysis.Category);
        Assert.Equal(BlockAdvice.SafeToBlock, analysis.Advice);
    }
}
