using System;
using System.Collections.Generic;
using System.Linq;

namespace SpectraNetworkManager.Core.Devices;

/// <summary>
/// Curated offline catalog of Automatic Content Recognition (ACR), viewing telemetry,
/// and advertising domains used by major Smart TV operating systems and streaming platforms.
/// </summary>
public static class TvTelemetryCatalog
{
    // Samsung Tizen TV ACR, telemetry, and smart ads
    public static readonly string[] SamsungTvDomains = new[]
    {
        "samsungacr.com",
        "sbd-samsung.com",
        "samsungads.com",
        "samsungcloudsolution.com",
        "vd.emp.samsung.com",
        "otn.samsungcloud.com",
        "log-config.samsungcloudsolution.com",
        "target.samsungads.com",
        "notice.samsungcloudsolution.com",
        "lcprd1.samsungcloudsolution.net",
        "gpm.samsungqbe.com",
        "time.samsungcloudsolution.com",
        "o2.samsungqbe.com",
        "cdn.samsungcloudsolution.com"
    };

    // LG webOS Smart TV ACR, diagnostics, and banner ad delivery
    public static readonly string[] LgTvDomains = new[]
    {
        "smartshare.lgtvsdp.com",
        "ibs.lgappstv.com",
        "lgsmartad.com",
        "rdx.lgtvsdp.com",
        "us.info.lgsmartad.com",
        "aic-ngfts.lge.com",
        "lgtvonline.lge.com",
        "ngfts.lge.com",
        "ad.lgappstv.com",
        "emp-live.lgtvsdp.com",
        "cdns.us.lgtvsdp.com"
    };

    // Roku OS telemetry, audience tracking, and ad delivery
    public static readonly string[] RokuTvDomains = new[]
    {
        "scribe.logs.roku.com",
        "cooper.logs.roku.com",
        "ads.roku.com",
        "track.sr.roku.com",
        "identity.web.roku.com",
        "austin.logs.roku.com",
        "richmond.logs.roku.com",
        "cloudservices.roku.com",
        "giga.logs.roku.com",
        "liberty.logs.roku.com"
    };

    // Sony Bravia & Android TV telemetry
    public static readonly string[] SonyTvDomains = new[]
    {
        "bravia.sony.com",
        "telemetry.sony.com",
        "pro-bravia.sony.net",
        "tvservices.sony.net",
        "api.bravia.sony.com",
        "sony-europe.com",
        "reg.sony-europe.com"
    };

    // Xiaomi / Mi TV PatchWall telemetry and analytics
    public static readonly string[] XiaomiTvDomains = new[]
    {
        "data.mistat.xiaomi.com",
        "tracking.miui.com",
        "ad.xiaomi.com",
        "api.ad.xiaomi.com",
        "log.tns-counter.ru",
        "metrika.yandex.ru"
    };

    // Philips / TP Vision Smart TV telemetry
    public static readonly string[] PhilipsTvDomains = new[]
    {
        "smarttv.tpvision.com",
        "nettv.corio.com",
        "useranalytics.tpvision.com"
    };

    // Apple TV / tvOS analytics and diagnostics (excluding App Store & streaming CDN)
    public static readonly string[] AppleTvDomains = new[]
    {
        "metrics.apple.com",
        "diagnostics.apple.com",
        "iadsdk.apple.com",
        "ac-assets.apple.com"
    };

    // Amazon Fire TV & Fire Stick telemetry
    public static readonly string[] AmazonFireTvDomains = new[]
    {
        "device-metrics-us.amazon.com",
        "device-metrics-us-2.amazon.com",
        "device-metrics.amazon.com",
        "amzdigitaldownloads.edgesuite.net"
    };

    /// <summary>
    /// Gets all ACR and telemetry domains aggregated across all Smart TV manufacturers.
    /// </summary>
    public static IReadOnlyList<string> GetAllSmartTvAcrDomains()
    {
        var all = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in SamsungTvDomains) all.Add(d);
        foreach (var d in LgTvDomains) all.Add(d);
        foreach (var d in RokuTvDomains) all.Add(d);
        foreach (var d in SonyTvDomains) all.Add(d);
        foreach (var d in XiaomiTvDomains) all.Add(d);
        foreach (var d in PhilipsTvDomains) all.Add(d);
        foreach (var d in AppleTvDomains) all.Add(d);
        foreach (var d in AmazonFireTvDomains) all.Add(d);
        return all.OrderBy(d => d).ToList();
    }

    /// <summary>
    /// Gets specific ACR and telemetry domains for a detected or selected vendor.
    /// </summary>
    public static IReadOnlyList<string> GetDomainsForVendor(string? vendor)
    {
        if (string.IsNullOrWhiteSpace(vendor))
            return GetAllSmartTvAcrDomains();

        string v = vendor.ToLowerInvariant();
        if (v.Contains("samsung")) return SamsungTvDomains;
        if (v.Contains("lg") || v.Contains("webos")) return LgTvDomains;
        if (v.Contains("roku")) return RokuTvDomains;
        if (v.Contains("sony") || v.Contains("bravia")) return SonyTvDomains;
        if (v.Contains("xiaomi") || v.Contains("mi")) return XiaomiTvDomains;
        if (v.Contains("philips") || v.Contains("tpv") || v.Contains("tp vision")) return PhilipsTvDomains;
        if (v.Contains("apple")) return AppleTvDomains;
        if (v.Contains("amazon") || v.Contains("fire")) return AmazonFireTvDomains;

        return GetAllSmartTvAcrDomains();
    }
}
