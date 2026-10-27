using System;
using System.Net;

namespace SpectraNetworkManager.Core.Devices;

/// <summary>
/// Status of a LAN device regarding SpectraNetworkManager DNS Sinkhole protection.
/// </summary>
public enum ProtectionLevel
{
    /// <summary>
    /// Device is sending DNS queries directly to SpectraNetworkManager. Full per-device filtering active.
    /// </summary>
    DirectProtected,

    /// <summary>
    /// DNS queries from this LAN subnet are being forwarded through the router gateway (e.g. 192.168.1.1).
    /// Global blocklists work, but per-device rules require pointing the device DNS directly to Spectra.
    /// </summary>
    GatewayRouted,

    /// <summary>
    /// Device is visible on the LAN (ARP / neighbor table), but no DNS queries have reached Spectra.
    /// Device may be using hardcoded DNS (e.g. 8.8.8.8) or is currently idle.
    /// </summary>
    BypassingOrInactive,

    /// <summary>
    /// Queries to known encrypted DNS (DoH/DoT) bootstrap domains detected from this device,
    /// indicating an attempt to bypass local DNS sinkhole.
    /// </summary>
    DohBypassRisk
}

public sealed record DeviceProtectionInfo(
    ProtectionLevel Level,
    string BadgeText,
    string StatusColor,
    string Description,
    string ActionableGuidance,
    DateTime? LastQueryTimeUtc,
    int TotalQueries,
    int BlockedQueries)
{
    public bool IsActive => Level == ProtectionLevel.DirectProtected;
}

public static class DeviceProtectionEvaluator
{
    public static DeviceProtectionInfo Evaluate(
        IPAddress deviceIp,
        IPAddress? routerGatewayIp,
        DateTime? lastSeenQueryUtc,
        int totalQueries,
        int blockedQueries,
        bool detectedDohAttempt)
    {
        if (detectedDohAttempt)
        {
            return new DeviceProtectionInfo(
                Level: ProtectionLevel.DohBypassRisk,
                BadgeText: "⚠️ DoH Bypass Risk",
                StatusColor: "#FF2BD6", // Magenta alert
                Description: "Encrypted DNS (DoH/DoT) bootstrap activity detected from this device.",
                ActionableGuidance: "Enable 'Block Browser DoH' in DNS settings or block outbound TCP/UDP port 853 and known DoH bootstrap domains.",
                LastQueryTimeUtc: lastSeenQueryUtc,
                TotalQueries: totalQueries,
                BlockedQueries: blockedQueries
            );
        }

        bool hasDirectRecentQueries = totalQueries > 0 && lastSeenQueryUtc.HasValue &&
            (DateTime.UtcNow - lastSeenQueryUtc.Value).TotalHours < 24;

        if (hasDirectRecentQueries)
        {
            var elapsed = DateTime.UtcNow - lastSeenQueryUtc!.Value;
            string timeStr = elapsed.TotalSeconds < 60 ? $"{(int)elapsed.TotalSeconds}s ago"
                : elapsed.TotalMinutes < 60 ? $"{(int)elapsed.TotalMinutes}m ago"
                : $"{(int)elapsed.TotalHours}h ago";

            return new DeviceProtectionInfo(
                Level: ProtectionLevel.DirectProtected,
                BadgeText: "🟢 Direct Protected",
                StatusColor: "#00E5FF", // Cyan / Green
                Description: $"Direct DNS queries active (Last query: {timeStr}).",
                ActionableGuidance: "Device is sending queries directly to Spectra. Group policies and custom blocklists are actively enforced.",
                LastQueryTimeUtc: lastSeenQueryUtc,
                TotalQueries: totalQueries,
                BlockedQueries: blockedQueries
            );
        }

        // If no direct queries, check if the router gateway is sending queries
        if (routerGatewayIp != null && !deviceIp.Equals(routerGatewayIp))
        {
            return new DeviceProtectionInfo(
                Level: ProtectionLevel.GatewayRouted,
                BadgeText: "🟡 Gateway Routed",
                StatusColor: "#FFB000", // Amber
                Description: $"Queries for this device appear to be forwarded via router gateway ({routerGatewayIp}).",
                ActionableGuidance: $"Your router is forwarding DNS on behalf of the LAN. Global blocking works, but to use per-device rules for this TV/GSM, set Spectra's IP as the DNS server in your device's Wi-Fi settings.",
                LastQueryTimeUtc: lastSeenQueryUtc,
                TotalQueries: totalQueries,
                BlockedQueries: blockedQueries
            );
        }

        return new DeviceProtectionInfo(
            Level: ProtectionLevel.BypassingOrInactive,
            BadgeText: "⚪ Inactive / Bypass",
            StatusColor: "#888888", // Gray
            Description: "Device is online on LAN, but zero DNS queries have reached Spectra.",
            ActionableGuidance: "Ensure device Wi-Fi DNS is pointed to this PC's LAN IP address, or verify whether the device uses hardcoded DNS (e.g. 8.8.8.8) or cellular data.",
            LastQueryTimeUtc: lastSeenQueryUtc,
            TotalQueries: totalQueries,
            BlockedQueries: blockedQueries
        );
    }
}
