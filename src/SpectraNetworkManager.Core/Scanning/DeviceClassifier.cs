using System.Text.RegularExpressions;

namespace SpectraNetworkManager.Core;

/// <summary>
/// Classifies devices on the local network (Smart TV, Mobile/Tablet, Router, Printer, IoT, Workstation)
/// using hardware MAC OUI prefixes, hostname patterns, and open service ports.
/// </summary>
public static class DeviceClassifier
{
    private sealed record OuiEntry(string Vendor, DeviceKind Kind);

    // Common hardware vendor MAC prefixes (normalized without colons/dashes, uppercase)
    private static readonly Dictionary<string, OuiEntry> OuiPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        // Smart TV & Streaming Media
        { "D83134", new OuiEntry("Roku, Inc.", DeviceKind.SmartTv) },
        { "B0EE7B", new OuiEntry("Roku, Inc.", DeviceKind.SmartTv) },
        { "B0A737", new OuiEntry("Roku, Inc.", DeviceKind.SmartTv) },
        { "84EA99", new OuiEntry("Roku, Inc.", DeviceKind.SmartTv) },
        { "000D4B", new OuiEntry("Roku, Inc.", DeviceKind.SmartTv) },
        { "CC6D10", new OuiEntry("Roku, Inc.", DeviceKind.SmartTv) },
        { "00E091", new OuiEntry("LG Electronics (webOS)", DeviceKind.SmartTv) },
        { "10F96F", new OuiEntry("LG Electronics (webOS)", DeviceKind.SmartTv) },
        { "203DB2", new OuiEntry("LG Electronics (webOS)", DeviceKind.SmartTv) },
        { "388C50", new OuiEntry("LG Electronics (webOS)", DeviceKind.SmartTv) },
        { "48E1E9", new OuiEntry("LG Electronics (webOS)", DeviceKind.SmartTv) },
        { "58FD7A", new OuiEntry("LG Electronics (webOS)", DeviceKind.SmartTv) },
        { "A823FE", new OuiEntry("LG Electronics (webOS)", DeviceKind.SmartTv) },
        { "C4366C", new OuiEntry("LG Electronics (webOS)", DeviceKind.SmartTv) },
        { "001247", new OuiEntry("Samsung Electronics (Smart TV)", DeviceKind.SmartTv) },
        { "002454", new OuiEntry("Samsung Electronics (Smart TV)", DeviceKind.SmartTv) },
        { "1449E0", new OuiEntry("Samsung Electronics (Smart TV)", DeviceKind.SmartTv) },
        { "281878", new OuiEntry("Samsung Electronics (Smart TV)", DeviceKind.SmartTv) },
        { "5492BE", new OuiEntry("Samsung Electronics (Smart TV)", DeviceKind.SmartTv) },
        { "682737", new OuiEntry("Samsung Electronics (Smart TV)", DeviceKind.SmartTv) },
        { "702C1F", new OuiEntry("Samsung Electronics (Smart TV)", DeviceKind.SmartTv) },
        { "F4F5DB", new OuiEntry("Samsung Electronics (Smart TV)", DeviceKind.SmartTv) },
        { "00014A", new OuiEntry("Sony Corporation (BRAVIA)", DeviceKind.SmartTv) },
        { "00041F", new OuiEntry("Sony Corporation (BRAVIA)", DeviceKind.SmartTv) },
        { "001315", new OuiEntry("Sony Corporation (BRAVIA)", DeviceKind.SmartTv) },
        { "001D0D", new OuiEntry("Sony Interactive (PlayStation)", DeviceKind.SmartTv) },
        { "0024BE", new OuiEntry("Sony Interactive (PlayStation)", DeviceKind.SmartTv) },
        { "709E29", new OuiEntry("Sony Interactive (PlayStation)", DeviceKind.SmartTv) },
        { "AC9B0A", new OuiEntry("Sony Corporation (BRAVIA)", DeviceKind.SmartTv) },
        { "0C47C9", new OuiEntry("Amazon Technologies (Fire TV / Echo)", DeviceKind.SmartTv) },
        { "34D270", new OuiEntry("Amazon Technologies (Fire TV / Echo)", DeviceKind.SmartTv) },
        { "44650D", new OuiEntry("Amazon Technologies (Fire TV / Echo)", DeviceKind.SmartTv) },
        { "68545A", new OuiEntry("Amazon Technologies (Fire TV / Echo)", DeviceKind.SmartTv) },
        { "747548", new OuiEntry("Amazon Technologies (Fire TV / Echo)", DeviceKind.SmartTv) },
        { "AC63BE", new OuiEntry("Amazon Technologies (Fire TV / Echo)", DeviceKind.SmartTv) },
        { "FC65DE", new OuiEntry("Amazon Technologies (Fire TV / Echo)", DeviceKind.SmartTv) },

        // Mobile / GSM / Tablet
        { "000393", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "0010FA", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "0017F2", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "001C81", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "001CB3", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "040CCE", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "18AF61", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "207D74", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "38CADA", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "40A6D9", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "48D705", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "5855CA", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "689C70", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "701124", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "88665A", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "A45E60", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "ACBC32", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "B03495", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "C869CD", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "D0817A", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "DC2B61", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "F01898", new OuiEntry("Apple Inc. (iPhone/iPad)", DeviceKind.MobileOrTablet) },
        { "001A79", new OuiEntry("Samsung Mobile (Galaxy)", DeviceKind.MobileOrTablet) },
        { "103047", new OuiEntry("Samsung Mobile (Galaxy)", DeviceKind.MobileOrTablet) },
        { "30CDA7", new OuiEntry("Samsung Mobile (Galaxy)", DeviceKind.MobileOrTablet) },
        { "5001D9", new OuiEntry("Samsung Mobile (Galaxy)", DeviceKind.MobileOrTablet) },
        { "78521A", new OuiEntry("Samsung Mobile (Galaxy)", DeviceKind.MobileOrTablet) },
        { "94B10A", new OuiEntry("Samsung Mobile (Galaxy)", DeviceKind.MobileOrTablet) },
        { "BC4486", new OuiEntry("Samsung Mobile (Galaxy)", DeviceKind.MobileOrTablet) },
        { "D4E6B7", new OuiEntry("Google (Pixel Phone)", DeviceKind.MobileOrTablet) },
        { "F40320", new OuiEntry("Google (Pixel Phone)", DeviceKind.MobileOrTablet) },
        { "183DA2", new OuiEntry("Google LLC", DeviceKind.MobileOrTablet) },
        { "180C56", new OuiEntry("Xiaomi Communications", DeviceKind.MobileOrTablet) },
        { "286CB8", new OuiEntry("Xiaomi Communications", DeviceKind.MobileOrTablet) },
        { "584498", new OuiEntry("Xiaomi Communications", DeviceKind.MobileOrTablet) },
        { "7CD1C3", new OuiEntry("OnePlus Electronics", DeviceKind.MobileOrTablet) },
        { "9809CF", new OuiEntry("OnePlus Electronics", DeviceKind.MobileOrTablet) },
        { "001E10", new OuiEntry("Huawei Device", DeviceKind.MobileOrTablet) },

        // Router & Gateways
        { "00040E", new OuiEntry("AVM Audiovisuelles (FRITZ!Box)", DeviceKind.RouterOrGateway) },
        { "001A4F", new OuiEntry("AVM Audiovisuelles (FRITZ!Box)", DeviceKind.RouterOrGateway) },
        { "0896D7", new OuiEntry("AVM Audiovisuelles (FRITZ!Box)", DeviceKind.RouterOrGateway) },
        { "3431C4", new OuiEntry("AVM Audiovisuelles (FRITZ!Box)", DeviceKind.RouterOrGateway) },
        { "3810D5", new OuiEntry("AVM Audiovisuelles (FRITZ!Box)", DeviceKind.RouterOrGateway) },
        { "444E6D", new OuiEntry("AVM Audiovisuelles (FRITZ!Box)", DeviceKind.RouterOrGateway) },
        { "9C3DCF", new OuiEntry("AVM Audiovisuelles (FRITZ!Box)", DeviceKind.RouterOrGateway) },
        { "C80E14", new OuiEntry("AVM Audiovisuelles (FRITZ!Box)", DeviceKind.RouterOrGateway) },
        { "DC15C8", new OuiEntry("AVM Audiovisuelles (FRITZ!Box)", DeviceKind.RouterOrGateway) },
        { "000C43", new OuiEntry("Ralink / Mediatek AP", DeviceKind.RouterOrGateway) },
        { "0014D1", new OuiEntry("TP-Link Technologies", DeviceKind.RouterOrGateway) },
        { "50C7BF", new OuiEntry("TP-Link Technologies", DeviceKind.RouterOrGateway) },
        { "60A44C", new OuiEntry("TP-Link Technologies", DeviceKind.RouterOrGateway) },
        { "B04E26", new OuiEntry("TP-Link Technologies", DeviceKind.RouterOrGateway) },
        { "D807B6", new OuiEntry("TP-Link Technologies", DeviceKind.RouterOrGateway) },
        { "00095B", new OuiEntry("NETGEAR, Inc.", DeviceKind.RouterOrGateway) },
        { "00146C", new OuiEntry("NETGEAR, Inc.", DeviceKind.RouterOrGateway) },
        { "20E52A", new OuiEntry("NETGEAR, Inc.", DeviceKind.RouterOrGateway) },
        { "9C3DC9", new OuiEntry("NETGEAR, Inc.", DeviceKind.RouterOrGateway) },
        { "C03FD5", new OuiEntry("NETGEAR, Inc.", DeviceKind.RouterOrGateway) },
        { "0015F2", new OuiEntry("ASUSTeK Computer (Router)", DeviceKind.RouterOrGateway) },
        { "049226", new OuiEntry("ASUSTeK Computer (Router)", DeviceKind.RouterOrGateway) },
        { "107B44", new OuiEntry("ASUSTeK Computer (Router)", DeviceKind.RouterOrGateway) },
        { "002722", new OuiEntry("Ubiquiti Networks (UniFi)", DeviceKind.RouterOrGateway) },
        { "24A43C", new OuiEntry("Ubiquiti Networks (UniFi)", DeviceKind.RouterOrGateway) },
        { "68D79A", new OuiEntry("Ubiquiti Networks (UniFi)", DeviceKind.RouterOrGateway) },
        { "74ACB9", new OuiEntry("Ubiquiti Networks (UniFi)", DeviceKind.RouterOrGateway) },
        { "B4FBE4", new OuiEntry("Ubiquiti Networks (UniFi)", DeviceKind.RouterOrGateway) },
        { "00000C", new OuiEntry("Cisco Systems", DeviceKind.RouterOrGateway) },
        { "001A2F", new OuiEntry("Cisco Systems", DeviceKind.RouterOrGateway) },
        { "48EE0C", new OuiEntry("MikroTik", DeviceKind.RouterOrGateway) },
        { "6C3B6B", new OuiEntry("MikroTik", DeviceKind.RouterOrGateway) },

        // Printers
        { "000074", new OuiEntry("Ricoh Co., Ltd.", DeviceKind.Printer) },
        { "0001E6", new OuiEntry("Hewlett-Packard (Printer)", DeviceKind.Printer) },
        { "000E7F", new OuiEntry("Hewlett-Packard (Printer)", DeviceKind.Printer) },
        { "001E0B", new OuiEntry("Hewlett-Packard (Printer)", DeviceKind.Printer) },
        { "3CD92B", new OuiEntry("Hewlett-Packard (Printer)", DeviceKind.Printer) },
        { "6C3BE5", new OuiEntry("Hewlett-Packard (Printer)", DeviceKind.Printer) },
        { "000085", new OuiEntry("Canon Inc. (Printer)", DeviceKind.Printer) },
        { "001E8F", new OuiEntry("Canon Inc. (Printer)", DeviceKind.Printer) },
        { "180C55", new OuiEntry("Canon Inc. (Printer)", DeviceKind.Printer) },
        { "000048", new OuiEntry("Seiko Epson Corp.", DeviceKind.Printer) },
        { "0026AB", new OuiEntry("Seiko Epson Corp.", DeviceKind.Printer) },
        { "AC1826", new OuiEntry("Seiko Epson Corp.", DeviceKind.Printer) },
        { "008077", new OuiEntry("Brother Industries", DeviceKind.Printer) },
        { "30055C", new OuiEntry("Brother Industries", DeviceKind.Printer) },

        // IoT / Smart Home
        { "18FE34", new OuiEntry("Espressif Inc. (ESP8266/ESP32)", DeviceKind.IotOrSmartHome) },
        { "240AC4", new OuiEntry("Espressif Inc. (ESP8266/ESP32)", DeviceKind.IotOrSmartHome) },
        { "246F28", new OuiEntry("Espressif Inc. (ESP8266/ESP32)", DeviceKind.IotOrSmartHome) },
        { "30AEA4", new OuiEntry("Espressif Inc. (ESP8266/ESP32)", DeviceKind.IotOrSmartHome) },
        { "440176", new OuiEntry("Espressif Inc. (Bitaxe / ESP32)", DeviceKind.IotOrSmartHome) },
        { "840D8E", new OuiEntry("Espressif Inc. (ESP8266/ESP32)", DeviceKind.IotOrSmartHome) },
        { "940100", new OuiEntry("Espressif Inc. (Bitaxe / ESP32)", DeviceKind.IotOrSmartHome) },
        { "A4CF12", new OuiEntry("Espressif Inc. (ESP8266/ESP32)", DeviceKind.IotOrSmartHome) },
        { "CC50E3", new OuiEntry("Espressif Inc. (ESP8266/ESP32)", DeviceKind.IotOrSmartHome) },
        { "ECFAB0", new OuiEntry("Espressif Inc. (ESP8266/ESP32)", DeviceKind.IotOrSmartHome) },
        { "D8B04C", new OuiEntry("Tuya Smart Inc. (IoT)", DeviceKind.IotOrSmartHome) },
        { "001788", new OuiEntry("Philips Lighting (Hue)", DeviceKind.IotOrSmartHome) },
        { "ECB5FA", new OuiEntry("Philips Lighting (Hue)", DeviceKind.IotOrSmartHome) },
        { "000E58", new OuiEntry("Sonos, Inc. (Smart Audio)", DeviceKind.IotOrSmartHome) },
        { "7828CA", new OuiEntry("Sonos, Inc. (Smart Audio)", DeviceKind.IotOrSmartHome) },
        { "B8E937", new OuiEntry("Sonos, Inc. (Smart Audio)", DeviceKind.IotOrSmartHome) },
        { "B827EB", new OuiEntry("Raspberry Pi Foundation", DeviceKind.IotOrSmartHome) },
        { "DCA632", new OuiEntry("Raspberry Pi Foundation", DeviceKind.IotOrSmartHome) },
        { "E45F01", new OuiEntry("Raspberry Pi Foundation", DeviceKind.IotOrSmartHome) },

        // Workstations / PCs
        { "001B21", new OuiEntry("Intel Corporation", DeviceKind.Workstation) },
        { "3417EB", new OuiEntry("Dell Inc.", DeviceKind.Workstation) },
        { "001422", new OuiEntry("Dell Inc.", DeviceKind.Workstation) },
        { "D4BED9", new OuiEntry("Dell Inc.", DeviceKind.Workstation) },
        { "00215A", new OuiEntry("HP Inc. (PC/Laptop)", DeviceKind.Workstation) },
        { "002655", new OuiEntry("Lenovo Group", DeviceKind.Workstation) },
        { "E86A64", new OuiEntry("Realtek Semiconductor", DeviceKind.Workstation) },
        { "00E04C", new OuiEntry("Realtek Semiconductor", DeviceKind.Workstation) },
        { "005056", new OuiEntry("VMware Virtual Adapter", DeviceKind.Workstation) },
        { "080027", new OuiEntry("VirtualBox Adapter", DeviceKind.Workstation) },
    };

    public static (DeviceKind Kind, string Vendor, string Description) Classify(
        string macAddress,
        string hostname,
        IReadOnlyList<DiscoveredPort>? openPorts = null,
        bool isGateway = false)
    {
        string normMac = NormalizeMac(macAddress);
        string normHost = (hostname ?? "").Trim().ToLowerInvariant();

        // 1. Gateway override
        if (isGateway)
        {
            string vendor = LookupVendor(normMac) ?? "Local Gateway";
            return (DeviceKind.RouterOrGateway, vendor, "Default Gateway / Internet Router");
        }

        // 2. Hardware MAC Prefix Check
        OuiEntry? ouiMatch = null;
        if (normMac.Length >= 6 && OuiPrefixes.TryGetValue(normMac[..6], out var foundOui))
        {
            ouiMatch = foundOui;
        }

        // 3. Port fingerprinting (very reliable for specific device classes)
        var portNumbers = openPorts?.Select(p => p.Port).ToHashSet() ?? new HashSet<int>();

        if (portNumbers.Contains(8060))
        {
            return (DeviceKind.SmartTv, "Roku Inc.", "Roku Streaming Device / TV (ECP port 8060 open)");
        }
        if (portNumbers.Contains(8008) || portNumbers.Contains(8009))
        {
            return (DeviceKind.SmartTv, ouiMatch?.Vendor ?? "Google", "Google Cast / Smart Display (Ports 8008/8009 open)");
        }
        if (portNumbers.Contains(9100) || portNumbers.Contains(515) || (portNumbers.Contains(631) && !portNumbers.Contains(22)))
        {
            return (DeviceKind.Printer, ouiMatch?.Vendor ?? "Network Printer", "Network Printer (RAW/LPD/IPP ports open)");
        }
        if (portNumbers.Contains(7000) || portNumbers.Contains(7100))
        {
            return (DeviceKind.SmartTv, "Apple Inc.", "Apple TV / AirPlay Receiver (Ports 7000/7100 open)");
        }
        if (portNumbers.Contains(5555) && ouiMatch?.Kind == DeviceKind.SmartTv)
        {
            return (DeviceKind.SmartTv, ouiMatch.Vendor, "Fire TV / Android TV (ADB Port 5555 open)");
        }

        // 4. Hostname pattern matching
        if (!string.IsNullOrEmpty(normHost))
        {
            if (Regex.IsMatch(normHost, @"\b(tv|smarttv|bravia|tizen|webos|roku|vizio|chromecast|firetv|appletv|shield|hisense|tcl)\b|lgwebostv|samsungtv|sonytv"))
            {
                return (DeviceKind.SmartTv, ouiMatch?.Vendor ?? "Smart TV", $"Smart TV / Media Streamer ({hostname})");
            }
            if (Regex.IsMatch(normHost, @"\b(iphone|ipad|galaxy|pixel|oneplus|xiaomi|redmi|huawei|android|phone|mobile)\b"))
            {
                return (DeviceKind.MobileOrTablet, ouiMatch?.Vendor ?? "Mobile Device", $"Mobile Phone / Tablet ({hostname})");
            }
            if (Regex.IsMatch(normHost, @"\b(printer|laserjet|deskjet|officejet|canon|epson|brother|xerox|kyocera)\b"))
            {
                return (DeviceKind.Printer, ouiMatch?.Vendor ?? "Printer", $"Network Printer ({hostname})");
            }
            if (Regex.IsMatch(normHost, @"\b(fritz|router|gateway|modem|unifi|netgear|tplink|linksys|asusrouter)\b"))
            {
                return (DeviceKind.RouterOrGateway, ouiMatch?.Vendor ?? "Router / Gateway", $"Network Gateway ({hostname})");
            }
            if (Regex.IsMatch(normHost, @"\b(hue|sonos|ring|nest|tuya|tasmota|shelly|esp8266|esp32|bitaxe|axe|miner|plug|cam|camera)\b"))
            {
                return (DeviceKind.IotOrSmartHome, ouiMatch?.Vendor ?? "IoT Device", $"Smart Home / IoT Device ({hostname})");
            }
            if (Regex.IsMatch(normHost, @"\b(nas|synology|qnap|truenas|server)\b"))
            {
                return (DeviceKind.ServerOrNas, ouiMatch?.Vendor ?? "Server / NAS", $"Network Storage / Server ({hostname})");
            }
        }

        // 5. Fallback to MAC OUI classification if available
        if (ouiMatch is not null)
        {
            return (ouiMatch.Kind, ouiMatch.Vendor, $"{ouiMatch.Vendor} ({ouiMatch.Kind})");
        }

        // 6. Generic computer / workstation if RDP/SMB/SSH open
        if (portNumbers.Contains(3389) || portNumbers.Contains(445) || portNumbers.Contains(135))
        {
            return (DeviceKind.Workstation, "Windows PC", "Windows PC / Workstation (SMB/RDP active)");
        }
        if (portNumbers.Contains(22) && portNumbers.Contains(80))
        {
            return (DeviceKind.ServerOrNas, "Linux / Embedded", "Network Host (SSH / Web Server active)");
        }

        return (DeviceKind.Unknown, "Unknown Vendor", "Network Device");
    }

    public static string? LookupVendor(string macAddress)
    {
        string norm = NormalizeMac(macAddress);
        if (norm.Length >= 6 && OuiPrefixes.TryGetValue(norm[..6], out var e))
        {
            return e.Vendor;
        }
        return null;
    }

    private static string NormalizeMac(string mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return "";
        return new string(mac.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
    }
}
