using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Tests;

public class DomainFilterTests
{
    [Fact]
    public void EmptyFilter_MatchesNothing()
    {
        var filter = DomainFilter.Empty;
        Assert.Equal(FilterAction.None, filter.Decide("example.com").Action);
        Assert.Equal(0, filter.BlockedDomainCount);
    }

    [Fact]
    public void HostsFile_ParsedCorrectly_BlocksDomainsAndSubdomains()
    {
        string hosts = @"
# This is a comment
127.0.0.1 localhost
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com tracker.example.net # inline comment
127.0.0.1 malicious.org
";
        var builder = new DomainFilterBuilder();
        var stats = builder.AddListText(hosts);
        Assert.Equal(3, stats.Blocked);
        Assert.Equal(0, stats.Allowed);

        var filter = builder.Build();
        Assert.Equal(3, filter.BlockedDomainCount);

        // Exact matches
        Assert.Equal(FilterAction.Blocked, filter.Decide("ads.example.com").Action);
        Assert.Equal(FilterAction.Blocked, filter.Decide("tracker.example.net").Action);
        Assert.Equal(FilterAction.Blocked, filter.Decide("malicious.org").Action);

        // Subdomain matches
        Assert.Equal(FilterAction.Blocked, filter.Decide("sub.ads.example.com").Action);
        Assert.Equal(FilterAction.Blocked, filter.Decide("deep.sub.tracker.example.net").Action);

        // Ignored hosts are not blocked
        Assert.Equal(FilterAction.None, filter.Decide("localhost").Action);

        // Unrelated domains
        Assert.Equal(FilterAction.None, filter.Decide("example.com").Action);
        Assert.Equal(FilterAction.None, filter.Decide("notmalicious.org").Action);
    }

    [Fact]
    public void AdblockSyntax_BlocksAndAllows()
    {
        string adblock = @"
[Adblock Plus 2.0]
! Title: Test List
||adserver.com^
||tracking.com^$third-party
@@||allowed-partner.adserver.com^
! Cosmetic rule that must be skipped
###ad-banner
";
        var builder = new DomainFilterBuilder();
        var stats = builder.AddListText(adblock);
        Assert.Equal(2, stats.Blocked);
        Assert.Equal(1, stats.Allowed);

        var filter = builder.Build();
        Assert.Equal(FilterAction.Blocked, filter.Decide("adserver.com").Action);
        Assert.Equal(FilterAction.Blocked, filter.Decide("popunder.tracking.com").Action);

        // Allow-rule overrides block-rule
        Assert.Equal(FilterAction.Allowed, filter.Decide("allowed-partner.adserver.com").Action);
        Assert.Equal(FilterAction.Allowed, filter.Decide("sub.allowed-partner.adserver.com").Action);
    }

    [Fact]
    public void AllowWinsOverBlock_Always()
    {
        var builder = new DomainFilterBuilder();
        builder.AddBlock("example.com");
        builder.AddAllow("good.example.com");

        var filter = builder.Build();
        Assert.Equal(FilterAction.Blocked, filter.Decide("example.com").Action);
        Assert.Equal(FilterAction.Blocked, filter.Decide("bad.example.com").Action);
        Assert.Equal(FilterAction.Allowed, filter.Decide("good.example.com").Action);
    }

    [Fact]
    public void RegexRule_MatchesAndBlocks()
    {
        var builder = new DomainFilterBuilder();
        builder.AddCustom(@"/^ad[0-9]+\.test$/", allow: false);
        builder.AddCustom(@"/^safe[0-9]+\.test$/", allow: true);

        var filter = builder.Build();
        Assert.Equal(FilterAction.Blocked, filter.Decide("ad42.test").Action);
        Assert.Equal(FilterAction.Blocked, filter.Decide("ad999.test").Action);
        Assert.Equal(FilterAction.None, filter.Decide("adtext.test").Action);
        Assert.Equal(FilterAction.Allowed, filter.Decide("safe1.test").Action);
    }

    [Fact]
    public void CustomWildcard_NormalizesCorrectly()
    {
        var builder = new DomainFilterBuilder();
        builder.AddCustom("*.telemetry.microsoft.com", allow: false);

        var filter = builder.Build();
        Assert.Equal(FilterAction.Blocked, filter.Decide("telemetry.microsoft.com").Action);
        Assert.Equal(FilterAction.Blocked, filter.Decide("v10.telemetry.microsoft.com").Action);
        Assert.Equal(FilterAction.None, filter.Decide("microsoft.com").Action);
    }
}
