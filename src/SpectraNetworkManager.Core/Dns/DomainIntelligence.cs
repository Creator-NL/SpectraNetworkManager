using System.Globalization;

namespace SpectraNetworkManager.Sinkhole;

public enum DomainCategory
{
    AdvertisingTracker,
    TelemetryAnalytics,
    SocialTracker,
    CdnInfrastructure,
    StreamingMedia,
    SystemCore,
    SearchEngine,
    GeneralWeb
}

public enum BlockAdvice
{
    SafeToBlock,
    CautionBreakagePossible,
    EssentialKeepAllowed,
    CurrentlyBlocked
}

public sealed record DomainAnalysis(
    string Domain,
    string RootDomain,
    DomainCategory Category,
    string CategoryName,
    string ServiceName,
    string Description,
    BlockAdvice Advice,
    string AdviceTitle,
    string AdviceDetail
);

/// <summary>
/// Provides local offline intelligence, categorization, and blocking recommendations for DNS queries.
/// </summary>
public static class DomainIntelligence
{
    private static readonly HashSet<string> KnownTwoPartTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz",
        "co.jp", "ne.jp", "ac.jp", "go.jp",
        "com.br", "net.br", "org.br",
        "com.mx", "org.mx", "edu.mx",
        "co.za", "org.za", "net.za",
        "co.in", "net.in", "org.in", "gen.in"
    };

    public static string GetRootDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return "";
        string clean = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var parts = clean.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 2) return clean;

        string lastTwo = parts[^2] + "." + parts[^1];
        if (KnownTwoPartTlds.Contains(lastTwo) && parts.Length >= 3)
        {
            return parts[^3] + "." + lastTwo;
        }

        return parts[^2] + "." + parts[^1];
    }

    public static DomainAnalysis Analyze(string domain, bool isBlocked = false, bool isFailed = false)
    {
        string norm = DomainFilter.Normalize(domain);
        string root = GetRootDomain(norm);

        // 1. YouTube & Google Video streaming
        if (norm.EndsWith("googlevideo.com", StringComparison.OrdinalIgnoreCase) ||
            norm.Contains(".googlevideo.") || norm.Equals("googlevideo.com", StringComparison.OrdinalIgnoreCase))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.StreamingMedia,
                CategoryName: "Media Streaming",
                ServiceName: "YouTube Video Delivery Stream",
                Description: "Serves audio and video stream segments for YouTube. Although some ads originate from here, blocking this domain directly prevents YouTube videos from playing or causes infinite buffering.",
                Advice: isBlocked ? BlockAdvice.CurrentlyBlocked : BlockAdvice.CautionBreakagePossible,
                AdviceTitle: isBlocked ? "Blocked (May Break YouTube)" : "Caution: Do Not Block",
                AdviceDetail: "Blocking googlevideo.com will break video playback on YouTube."
            );
        }

        if (norm.EndsWith("ytimg.com", StringComparison.OrdinalIgnoreCase) ||
            norm.Equals("ytimg.com", StringComparison.OrdinalIgnoreCase))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.StreamingMedia,
                CategoryName: "Media Streaming",
                ServiceName: "YouTube Static Media & Thumbnails",
                Description: "Hosts YouTube video thumbnails, preview images, and player UI assets.",
                Advice: isBlocked ? BlockAdvice.CurrentlyBlocked : BlockAdvice.CautionBreakagePossible,
                AdviceTitle: isBlocked ? "Blocked" : "Caution: May Break Thumbnails",
                AdviceDetail: "Blocking this will make YouTube thumbnails and icons appear broken or blank."
            );
        }

        // 2. Google Ads, Telemetry & DoubleClick
        if (root.Equals("doubleclick.net", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("googleadservices.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("googlesyndication.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("googletagmanager.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("googletagservices.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("google-analytics.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("admob.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("2mdn.net", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("gvt1.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("gvt2.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("gvt3.com", StringComparison.OrdinalIgnoreCase))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.AdvertisingTracker,
                CategoryName: "Advertising & Trackers",
                ServiceName: "Google Ads & Conversion Analytics",
                Description: "Ad delivery, conversion tracking, and analytics network embedded across websites and apps to serve targeted ads.",
                Advice: isBlocked ? BlockAdvice.CurrentlyBlocked : BlockAdvice.SafeToBlock,
                AdviceTitle: isBlocked ? "Blocked (Safe)" : "Safe to Block",
                AdviceDetail: "Stops Google tracking and display ads without affecting Google search or login."
            );
        }

        // 3. Microsoft Telemetry & MSN Analytics
        if (norm.Contains("msn.com") || norm.Contains("data.microsoft.com") ||
            norm.Contains("telemetry.microsoft.com") || norm.Contains("pipe.aria.microsoft.com") ||
            norm.Contains("activity.windows.com") || norm.Contains("watson.telemetry"))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.TelemetryAnalytics,
                CategoryName: "Operating System Telemetry",
                ServiceName: "Microsoft Diagnostic & MSN Telemetry",
                Description: "Windows, Edge, and MSN diagnostic data collection pipeline used for telemetry reporting, user telemetry, and newsfeed tracking.",
                Advice: isBlocked ? BlockAdvice.CurrentlyBlocked : BlockAdvice.SafeToBlock,
                AdviceTitle: isBlocked ? "Blocked (Safe)" : "Safe to Block",
                AdviceDetail: "Safe to block. Stops background telemetry collection. Windows Update and Store remain functional."
            );
        }

        // 4. Commercial Ad Exchanges & Retargeting Networks
        if (root.Equals("criteo.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("criteo.net", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("adnxs.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("appnexus.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("rubiconproject.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("magnite.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("taboola.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("outbrain.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("pubmatic.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("casalemedia.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("indexexchange.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("openx.net", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("scorecardresearch.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("quantserve.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("moatads.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("amazon-adsystem.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("hotjar.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("clarity.ms", StringComparison.OrdinalIgnoreCase))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.AdvertisingTracker,
                CategoryName: "Advertising & Trackers",
                ServiceName: GetAdNetworkName(root),
                Description: "Commercial ad exchange, retargeting platform, or behavioral tracking network monitoring your web browsing.",
                Advice: isBlocked ? BlockAdvice.CurrentlyBlocked : BlockAdvice.SafeToBlock,
                AdviceTitle: isBlocked ? "Blocked (Safe)" : "Safe to Block",
                AdviceDetail: "Eliminates third-party ad bidding and tracking with zero impact on site functionality."
            );
        }

        // 5. Social Media Trackers & Pixels
        if (root.Equals("facebook.net", StringComparison.OrdinalIgnoreCase) ||
            norm.Contains("pixel.facebook") || norm.Contains("connect.facebook") ||
            root.Equals("tiktokv.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("byteoversea.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("ibytedtos.com", StringComparison.OrdinalIgnoreCase) ||
            norm.Contains("ads-twitter.com") || norm.Contains("analytics.twitter"))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.SocialTracker,
                CategoryName: "Social Media Tracker",
                ServiceName: "Social Tracking Pixel & Graph API",
                Description: "Tracks browsing activity across third-party websites and links page visits back to your social media account profile.",
                Advice: isBlocked ? BlockAdvice.CurrentlyBlocked : BlockAdvice.SafeToBlock,
                AdviceTitle: isBlocked ? "Blocked (Safe)" : "Safe to Block",
                AdviceDetail: "Blocks cross-site tracking pixels and telemetry."
            );
        }

        // 6. CDNs & Essential Infrastructure
        if (root.Equals("cloudflare.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("cloudflare-dns.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("akamaized.net", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("akamaihd.net", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("akamai.net", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("fastly.net", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("fastlylb.net", StringComparison.OrdinalIgnoreCase))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.CdnInfrastructure,
                CategoryName: "CDN & Edge Infrastructure",
                ServiceName: "Global Content Delivery Network",
                Description: "High-performance edge CDN delivering essential web libraries, styles, and multimedia assets.",
                Advice: BlockAdvice.EssentialKeepAllowed,
                AdviceTitle: "Essential: Keep Allowed",
                AdviceDetail: "Caution: Do not block. Blocking this CDN will break images, scripts, and layouts across many websites."
            );
        }

        if (root.Equals("cloudfront.net", StringComparison.OrdinalIgnoreCase))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.CdnInfrastructure,
                CategoryName: "CDN Infrastructure",
                ServiceName: "Amazon CloudFront CDN",
                Description: "Amazon edge CDN caching assets and media for thousands of websites and applications.",
                Advice: BlockAdvice.CautionBreakagePossible,
                AdviceTitle: "Caution: May Break Sites",
                AdviceDetail: "Used by many websites to host styles and scripts. Blocking CloudFront often breaks web pages."
            );
        }

        // 7. Core OS & Browser Updates
        if (root.Equals("windowsupdate.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("update.microsoft.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("mozilla.org", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("mozilla.net", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("digicert.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("letsencrypt.org", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("sectigo.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("github.com", StringComparison.OrdinalIgnoreCase) ||
            root.Equals("githubusercontent.com", StringComparison.OrdinalIgnoreCase))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.SystemCore,
                CategoryName: "Core System / Security",
                ServiceName: "Operating System & Security Infrastructure",
                Description: "Essential infrastructure for software updates, digital certificate validation, or code repositories.",
                Advice: BlockAdvice.EssentialKeepAllowed,
                AdviceTitle: "Essential: Keep Allowed",
                AdviceDetail: "Required for system security, software updates, and HTTPS certificate verification."
            );
        }

        // 8. Keyword-based heuristics for unknown domains
        if (ContainsAdOrTrackingKeyword(norm))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.AdvertisingTracker,
                CategoryName: "Advertising / Tracking (Heuristic)",
                ServiceName: "Ad or Analytics Host",
                Description: "Domain name contains advertising, telemetry, or tracking keywords.",
                Advice: isBlocked ? BlockAdvice.CurrentlyBlocked : BlockAdvice.SafeToBlock,
                AdviceTitle: isBlocked ? "Blocked (Ad/Tracker)" : "Likely Safe to Block",
                AdviceDetail: "Appears to be an ad or tracking server based on domain keywords."
            );
        }

        if (norm.Contains("cdn.") || norm.Contains("static.") || norm.Contains("assets.") || norm.Contains("media."))
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.CdnInfrastructure,
                CategoryName: "Static Asset / CDN Host",
                ServiceName: "Content / Media Host",
                Description: "Domain likely serves static images, scripts, stylesheets, or media.",
                Advice: isBlocked ? BlockAdvice.CurrentlyBlocked : BlockAdvice.CautionBreakagePossible,
                AdviceTitle: isBlocked ? "Blocked" : "Caution: May Break Assets",
                AdviceDetail: "Hosts static files or media. Blocking might cause missing images or broken stylesheets."
            );
        }

        // 9. General fallback
        if (isBlocked)
        {
            return new DomainAnalysis(
                Domain: norm,
                RootDomain: root,
                Category: DomainCategory.GeneralWeb,
                CategoryName: "Filtered Domain",
                ServiceName: root,
                Description: "This domain was blocked by your active sinkhole filter rules or block lists.",
                Advice: BlockAdvice.CurrentlyBlocked,
                AdviceTitle: "Currently Blocked",
                AdviceDetail: "Blocked by sinkhole. If a website or app you use is failing, click 'Always Allow' to unblock it."
            );
        }

        return new DomainAnalysis(
            Domain: norm,
            RootDomain: root,
            Category: DomainCategory.GeneralWeb,
            CategoryName: "Standard Web Service",
            ServiceName: root,
            Description: $"Regular web domain query for {root}.",
            Advice: BlockAdvice.SafeToBlock,
            AdviceTitle: "Forwarded / Allowed",
            AdviceDetail: "If this domain delivers unwanted ads, popups, or tracking, click 'Always Block' to sinkhole it."
        );
    }

    private static bool ContainsAdOrTrackingKeyword(string domain)
    {
        string lower = domain.ToLowerInvariant();
        return lower.Contains("adserver", StringComparison.Ordinal) ||
               lower.Contains("telemetry", StringComparison.Ordinal) ||
               lower.Contains("analytics", StringComparison.Ordinal) ||
               lower.Contains("tracker", StringComparison.Ordinal) ||
               lower.Contains("tracking", StringComparison.Ordinal) ||
               lower.Contains("beacon", StringComparison.Ordinal) ||
               lower.Contains(".ads.", StringComparison.Ordinal) ||
               lower.StartsWith("ads.", StringComparison.Ordinal) ||
               lower.StartsWith("ad.", StringComparison.Ordinal) ||
               lower.Contains("pixel.", StringComparison.Ordinal) ||
               lower.Contains("metric.", StringComparison.Ordinal) ||
               lower.Contains("sponsor", StringComparison.Ordinal);
    }

    private static string GetAdNetworkName(string root) => root.ToLowerInvariant() switch
    {
        "criteo.com" or "criteo.net" => "Criteo Dynamic Retargeting",
        "adnxs.com" or "appnexus.com" => "Xandr / AppNexus Ad Exchange",
        "rubiconproject.com" or "magnite.com" => "Magnite / Rubicon Ad Bidding",
        "taboola.com" => "Taboola Sponsored Content Engine",
        "outbrain.com" => "Outbrain Sponsored Recommendation Engine",
        "pubmatic.com" => "PubMatic Header Bidding Platform",
        "casalemedia.com" or "indexexchange.com" => "Index Exchange Ad Marketplace",
        "openx.net" => "OpenX Programmatic Exchange",
        "scorecardresearch.com" => "Comscore Market Research & Tracking",
        "quantserve.com" => "Quantcast Audience Measurement",
        "moatads.com" => "Oracle Moat Ad Measurement",
        "amazon-adsystem.com" => "Amazon Sponsored Products Advertising",
        "hotjar.com" => "Hotjar User Heatmap & Session Tracking",
        "clarity.ms" => "Microsoft Clarity Session Analytics",
        _ => "Advertising & Tracking Platform"
    };
}
