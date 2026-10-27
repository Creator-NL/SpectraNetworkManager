using System;
using System.Collections.Generic;
using System.Linq;

namespace SpectraNetworkManager.Core.Devices;

/// <summary>
/// Curated catalog of mobile in-app advertising networks, device fingerprinting beacons,
/// and attribution/tracking SDKs commonly embedded in iOS and Android mobile apps.
/// </summary>
public static class MobileTelemetryCatalog
{
    // Mobile attribution & analytics SDKs (track user install, device ID, location, cross-app behavior)
    public static readonly string[] MobileAttributionDomains = new[]
    {
        "adjust.com",
        "app.adjust.com",
        "appsflyer.com",
        "app.appsflyer.com",
        "t.appsflyer.com",
        "branch.io",
        "api2.branch.io",
        "app.link",
        "kochava.com",
        "api.kochava.com",
        "singular.net",
        "c.singular.net",
        "flurry.com",
        "data.flurry.com",
        "tenjin.io",
        "track.tenjin.io",
        "tune.com"
    };

    // In-app interstitial, video rewarded, and banner ad networks
    public static readonly string[] MobileAdNetworkDomains = new[]
    {
        "unityads.unity3d.com",
        "auction.unityads.unity3d.com",
        "ironsrc.com",
        "supersonicads.com",
        "applovin.com",
        "rt.applovin.com",
        "inmobi.com",
        "config.inmobi.com",
        "vungle.com",
        "ads.vungle.com",
        "chartboost.com",
        "live.chartboost.com",
        "liftoff.io",
        "mintegral.com",
        "pgl.yandex.ru",
        "mobvista.com",
        "adcolony.com"
    };

    // Social & telemetry tracking SDKs in mobile apps
    public static readonly string[] MobileSocialTrackingDomains = new[]
    {
        "graph.facebook.com",
        "b-graph.facebook.com",
        "ads-twitter.com",
        "analytics.tiktok.com",
        "byteoversea.com",
        "log.byteoversea.com",
        "mon.byteoversea.com"
    };

    /// <summary>
    /// Gets all mobile tracking, ad network, and attribution SDK domains.
    /// </summary>
    public static IReadOnlyList<string> GetAllMobileTrackingDomains()
    {
        var all = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in MobileAttributionDomains) all.Add(d);
        foreach (var d in MobileAdNetworkDomains) all.Add(d);
        foreach (var d in MobileSocialTrackingDomains) all.Add(d);
        return all.OrderBy(d => d).ToList();
    }
}
