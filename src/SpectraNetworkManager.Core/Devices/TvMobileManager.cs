using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Core.Devices;

/// <summary>
/// Manages Smart TV and Mobile/GSM device profiles, DNS ClientGroup mappings,
/// vendor-specific telemetry/ACR filtering, and step-by-step DNS onboarding guidance.
/// </summary>
public sealed class TvMobileManager
{
    public const string SmartTvsGroupName = "Smart TVs";
    public const string MobileDevicesGroupName = "Mobile / GSM";

    /// <summary>
    /// Ensures predefined Smart TVs and Mobile Devices client groups exist in DNS settings.
    /// </summary>
    public static void EnsureDefaultGroups(DnsSettings settings)
    {
        if (settings.ClientGroups.All(g => !g.Name.Equals(SmartTvsGroupName, StringComparison.OrdinalIgnoreCase)))
        {
            var tvGroup = new ClientGroup
            {
                Name = SmartTvsGroupName,
                BlockingEnabled = true,
                CustomBlock = TvTelemetryCatalog.GetAllSmartTvAcrDomains().ToList()
            };
            settings.ClientGroups.Add(tvGroup);
        }

        if (settings.ClientGroups.All(g => !g.Name.Equals(MobileDevicesGroupName, StringComparison.OrdinalIgnoreCase)))
        {
            var mobileGroup = new ClientGroup
            {
                Name = MobileDevicesGroupName,
                BlockingEnabled = true,
                CustomBlock = MobileTelemetryCatalog.GetAllMobileTrackingDomains().ToList()
            };
            settings.ClientGroups.Add(mobileGroup);
        }
    }

    /// <summary>
    /// Assigns a device IP address to a named ClientGroup, optionally applying ACR or mobile presets.
    /// </summary>
    public static bool AssignDeviceToGroup(
        DnsSettings settings,
        string deviceIp,
        string groupName,
        string? vendorHint = null,
        bool applyAcrPreset = true)
    {
        if (string.IsNullOrWhiteSpace(deviceIp) || !IPAddress.TryParse(deviceIp, out _))
            return false;

        EnsureDefaultGroups(settings);

        // Remove device IP from any other group first
        foreach (var g in settings.ClientGroups)
        {
            g.ClientRanges.RemoveAll(r => r.Trim().Equals(deviceIp.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        var targetGroup = settings.ClientGroups.FirstOrDefault(g => g.Name.Equals(groupName, StringComparison.OrdinalIgnoreCase));
        if (targetGroup == null)
        {
            targetGroup = new ClientGroup
            {
                Name = groupName,
                BlockingEnabled = true
            };
            settings.ClientGroups.Add(targetGroup);
        }

        if (!targetGroup.ClientRanges.Contains(deviceIp))
        {
            targetGroup.ClientRanges.Add(deviceIp);
        }

        if (applyAcrPreset)
        {
            IReadOnlyList<string> presetDomains;
            if (groupName.Equals(SmartTvsGroupName, StringComparison.OrdinalIgnoreCase))
            {
                presetDomains = TvTelemetryCatalog.GetDomainsForVendor(vendorHint);
            }
            else if (groupName.Equals(MobileDevicesGroupName, StringComparison.OrdinalIgnoreCase))
            {
                presetDomains = MobileTelemetryCatalog.GetAllMobileTrackingDomains();
            }
            else
            {
                presetDomains = Array.Empty<string>();
            }

            foreach (var d in presetDomains)
            {
                if (!targetGroup.CustomBlock.Contains(d, StringComparer.OrdinalIgnoreCase))
                {
                    targetGroup.CustomBlock.Add(d);
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Toggles blocking on or off for a specific group.
    /// </summary>
    public static bool SetGroupBlocking(DnsSettings settings, string groupName, bool enabled)
    {
        var group = settings.ClientGroups.FirstOrDefault(g => g.Name.Equals(groupName, StringComparison.OrdinalIgnoreCase));
        if (group == null) return false;
        group.BlockingEnabled = enabled;
        return true;
    }

    /// <summary>
    /// Returns step-by-step DNS onboarding instructions formatted for display to the user.
    /// </summary>
    public static string GetDnsSetupGuide(string? vendor, string spectraLanIp)
    {
        string v = (vendor ?? "").ToLowerInvariant();

        if (v.Contains("samsung"))
        {
            return "Samsung Smart TV (Tizen OS):\n" +
                   "1. Press HOME or Settings on your Samsung remote.\n" +
                   "2. Go to Settings ➔ General ➔ Network ➔ Network Status.\n" +
                   "3. Select IP Settings ➔ DNS Setting ➔ Enter Manually.\n" +
                   $"4. Enter DNS Server: {spectraLanIp}\n" +
                   "5. Click OK. All Samsung ACR viewing trackers & ads are now blocked!";
        }

        if (v.Contains("lg") || v.Contains("webos"))
        {
            return "LG Smart TV (webOS):\n" +
                   "1. Press Gear/Settings on your LG remote.\n" +
                   "2. Go to All Settings ➔ Network ➔ Wi-Fi Connection (or Ethernet).\n" +
                   "3. Select Advanced Wi-Fi Settings ➔ Edit.\n" +
                   "4. Uncheck 'Set Automatically'.\n" +
                   $"5. Change DNS Server to: {spectraLanIp}\n" +
                   "6. Click Connect. Live Content Recognition & banner ads are now blocked!";
        }

        if (v.Contains("roku"))
        {
            return "Roku Streaming Stick / Roku TV:\n" +
                   "Note: Roku devices do not allow manual DNS configuration on the TV itself.\n" +
                   "To protect your Roku:\n" +
                   $"1. Open your Wi-Fi Router's administration page (e.g. 192.168.1.1).\n" +
                   $"2. Go to DHCP / LAN Settings and set Primary DNS to: {spectraLanIp}\n" +
                   "3. Restart your Roku. All Roku audience tracking & telemetry will be filtered!";
        }

        if (v.Contains("apple"))
        {
            return "Apple TV / iOS Device:\n" +
                   "1. Open Settings ➔ Network ➔ Select your Wi-Fi network.\n" +
                   "2. Click Configure DNS ➔ Select Manual.\n" +
                   $"3. Add DNS Server: {spectraLanIp}\n" +
                   "4. Save. App telemetry & tracking beacons will be sinkholed!";
        }

        if (v.Contains("android") || v.Contains("sony") || v.Contains("google"))
        {
            return "Android TV / Google TV / Android Phone:\n" +
                   "1. Open Settings ➔ Network & Internet ➔ Wi-Fi.\n" +
                   "2. Select your connected network ➔ Modify / Advanced Options.\n" +
                   "3. Change IP Settings from DHCP to Static (keep current IP & Gateway).\n" +
                   $"4. Set DNS 1 to: {spectraLanIp}\n" +
                   "5. Save. Ad networks and tracking SDKs will be blocked!";
        }

        // Generic guide
        return "Universal Smart TV & Mobile Device Setup:\n" +
               "1. Open Wi-Fi / Network Settings on your device.\n" +
               "2. Select your connected Wi-Fi network ➔ Configure IP / DNS.\n" +
               "3. Change DNS Mode to 'Manual' or 'Static'.\n" +
               $"4. Set DNS Server to: {spectraLanIp}\n" +
               "5. Save and reconnect. Telemetry and ads will be filtered automatically!";
    }
}
