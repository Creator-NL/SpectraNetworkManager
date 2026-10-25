using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Platform.Windows;

public sealed class WindowsSystemDnsSwitch : ISystemDnsSwitch
{
    private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(15);

    private static readonly string[] IgnoredNoiseKeywords =
    [
        "WAN Miniport",
        "Microsoft Kernel Debug",
        "Microsoft Wi-Fi Direct Virtual",
        "Microsoft Hosted Network",
        "Teredo",
        "isatap",
        "6to4",
        "IP-HTTPS",
        "RAS Async",
        "Npcap Loopback",
        "KM-TEST"
    ];

    private static readonly string[] KnownVirtualKeywords =
    [
        "Hyper-V Virtual",
        "vEthernet",
        "VMware Network Adapter",
        "VirtualBox Host-Only",
        "TAP-Windows",
        "Wintun",
        "WireGuard",
        "Tailscale",
        "ZeroTier",
        "NordLynx",
        "ProtonVPN",
        "OpenVPN",
        "Cisco AnyConnect",
        "Fortinet",
        "PANGP",
        "Hamachi",
        "Radmin VPN"
    ];

    private static readonly string[] KnownPhysicalVendorKeywords =
    [
        "Realtek",
        "PCIe",
        "GbE",
        "Family Controller",
        "RTL8",
        "Dragon",
        "Intel",
        "I219",
        "I211",
        "I225",
        "I226",
        "PRO/1000",
        "Killer",
        "Broadcom",
        "NetXtreme",
        "NetLink",
        "Qualcomm",
        "Atheros",
        "MediaTek",
        "MT79",
        "RZ6",
        "Marvell",
        "Aquantia",
        "AQtion",
        "NVIDIA nForce",
        "ASUS",
        "ROG",
        "TUF",
        "TP-Link",
        "D-Link",
        "Netgear",
        "ASIX"
    ];

    private static readonly string[] WirelessKeywords =
    [
        "Wi-Fi",
        "WiFi",
        "Wireless",
        "802.11",
        "WLAN",
        "Centrino",
        "AX200",
        "AX201",
        "AX210",
        "AX211",
        "BE200",
        "RZ608",
        "RZ616",
        "MT7921",
        "MT7922"
    ];

    /// <summary>
    /// Classifies a network interface, ensuring physical Ethernet (including ASUS / Realtek PCIe GbE with NDIS filters)
    /// and Wi-Fi adapters are never falsely hidden as virtual.
    /// </summary>
    public static (bool IsNoise, bool IsVirtual, bool IsWireless, string AdapterKind) ClassifyAdapter(
        string name,
        string description,
        NetworkInterfaceType type,
        bool hasDefaultGateway,
        bool wmiReportedVirtual = false)
    {
        string combined = $"{name} {description}";

        if (type == NetworkInterfaceType.Loopback)
        {
            return (true, true, false, "Loopback");
        }

        foreach (var noise in IgnoredNoiseKeywords)
        {
            if (combined.Contains(noise, StringComparison.OrdinalIgnoreCase))
            {
                return (true, true, false, "System Miniport");
            }
        }

        bool isWireless = type == NetworkInterfaceType.Wireless80211;
        if (!isWireless)
        {
            foreach (var kw in WirelessKeywords)
            {
                if (combined.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    isWireless = true;
                    break;
                }
            }
        }

        bool matchesKnownVirtual = type == NetworkInterfaceType.Tunnel;
        if (!matchesKnownVirtual)
        {
            foreach (var kw in KnownVirtualKeywords)
            {
                if (combined.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    matchesKnownVirtual = true;
                    break;
                }
            }
        }

        bool matchesKnownPhysical = false;
        foreach (var kw in KnownPhysicalVendorKeywords)
        {
            if (combined.Contains(kw, StringComparison.OrdinalIgnoreCase))
            {
                matchesKnownPhysical = true;
                break;
            }
        }

        // Key fix for ASUS / Realtek PCIe GbE controllers and bridged setups:
        // 1. If the adapter carries an active Default Gateway, it is the primary internet connection -> NEVER hide as virtual.
        // 2. If it matches a physical hardware vendor (Realtek, Intel, Killer, Broadcom, Qualcomm, MediaTek, ASUS, etc.)
        //    and isn't a known VPN/hypervisor virtual NIC, it is physical even if WMI flags Virtual=true due to GameFirst/Turbo LAN/NDIS filters.
        bool isVirtual;
        if (hasDefaultGateway)
        {
            isVirtual = false;
        }
        else if (matchesKnownVirtual)
        {
            isVirtual = true;
        }
        else if (matchesKnownPhysical || isWireless)
        {
            isVirtual = false;
        }
        else if (type is NetworkInterfaceType.Ethernet
                      or NetworkInterfaceType.GigabitEthernet
                      or NetworkInterfaceType.FastEthernetT
                      or NetworkInterfaceType.FastEthernetFx
                      or NetworkInterfaceType.Ethernet3Megabit)
        {
            isVirtual = false;
        }
        else
        {
            isVirtual = wmiReportedVirtual;
        }

        string kind = matchesKnownVirtual
            ? "Virtual / VPN"
            : (isWireless ? "Wi-Fi" : (isVirtual ? "Virtual / VPN" : "Ethernet"));

        return (false, isVirtual, isWireless, kind);
    }

    public async Task<IReadOnlyList<NetworkAdapterDnsInfo>> GetAdaptersAsync(CancellationToken ct = default)
    {
        // Layer 1: Fast, in-process Win32 IP Helper API + Registry inspection (works in Standard User & Admin modes, < 5ms)
        var nativeAdapters = GetAdaptersNative();
        if (nativeAdapters.Count > 0)
        {
            return nativeAdapters;
        }

        // Layer 2: PowerShell fallback (without the broken -not $_.Virtual filter) if native enumeration returned 0
        return await GetAdaptersPowerShellFallbackAsync(ct).ConfigureAwait(false);
    }

    public static IReadOnlyList<NetworkAdapterDnsInfo> GetAdaptersNative()
    {
        var results = new List<NetworkAdapterDnsInfo>();

        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var ni in interfaces)
            {
                try
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    // Include 'Up' interfaces (and Dormant/Unknown only if they carry a default gateway)
                    bool isUp = ni.OperationalStatus == OperationalStatus.Up;

                    IPInterfaceProperties ipProps;
                    try
                    {
                        ipProps = ni.GetIPProperties();
                    }
                    catch
                    {
                        continue;
                    }

                    bool hasGateway = false;
                    try
                    {
                        foreach (var gw in ipProps.GatewayAddresses)
                        {
                            if (gw?.Address is { } addr &&
                                !addr.Equals(IPAddress.Any) &&
                                !addr.Equals(IPAddress.IPv6Any) &&
                                !addr.Equals(IPAddress.None))
                            {
                                hasGateway = true;
                                break;
                            }
                        }
                    }
                    catch { }

                    if (!isUp && !hasGateway) continue;

                    int ifIndex = -1;
                    try
                    {
                        if (ni.Supports(NetworkInterfaceComponent.IPv4))
                        {
                            ifIndex = ipProps.GetIPv4Properties()?.Index ?? -1;
                        }
                    }
                    catch { }

                    if (ifIndex <= 0)
                    {
                        try
                        {
                            if (ni.Supports(NetworkInterfaceComponent.IPv6))
                            {
                                ifIndex = ipProps.GetIPv6Properties()?.Index ?? -1;
                            }
                        }
                        catch { }
                    }

                    if (ifIndex <= 0) continue;

                    string name = ni.Name ?? $"Adapter {ifIndex}";
                    string desc = ni.Description ?? name;
                    string guid = ni.Id ?? "";

                    var (isNoise, isVirtual, isWireless, kind) = ClassifyAdapter(
                        name, desc, ni.NetworkInterfaceType, hasGateway);

                    if (isNoise) continue;

                    // Extract current IPv4 and IPv6 DNS servers from IP Helper API
                    var v4Servers = new List<string>();
                    var v6Servers = new List<string>();

                    try
                    {
                        foreach (var dns in ipProps.DnsAddresses)
                        {
                            if (dns.AddressFamily == AddressFamily.InterNetwork)
                            {
                                string s = dns.ToString();
                                if (!v4Servers.Contains(s, StringComparer.OrdinalIgnoreCase))
                                    v4Servers.Add(s);
                            }
                            else if (dns.AddressFamily == AddressFamily.InterNetworkV6)
                            {
                                string s = dns.ToString();
                                // Strip scope ID (%12) if present
                                int pct = s.IndexOf('%');
                                if (pct > 0) s = s[..pct];

                                // Skip Windows default unconfigured site-local fec0:0:0:ffff:: placeholders
                                if (s.StartsWith("fec0:0:0:ffff:", StringComparison.OrdinalIgnoreCase))
                                    continue;

                                if (!v6Servers.Contains(s, StringComparer.OrdinalIgnoreCase))
                                    v6Servers.Add(s);
                            }
                        }
                    }
                    catch { }

                    // Inspect Registry to determine whether DNS is statically set (NameServer) or DHCP (DhcpNameServer)
                    var (regV4Static, regV4Servers) = ReadRegistryDnsServers(
                        $@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}");
                    var (regV6Static, regV6Servers) = ReadRegistryDnsServers(
                        $@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{guid}");

                    bool v4IsDhcp = !regV4Static;
                    bool v6IsDhcp = !regV6Static;

                    foreach (var s in regV4Servers)
                    {
                        if (!v4Servers.Contains(s, StringComparer.OrdinalIgnoreCase))
                            v4Servers.Add(s);
                    }

                    foreach (var s in regV6Servers)
                    {
                        if (!v6Servers.Contains(s, StringComparer.OrdinalIgnoreCase))
                            v6Servers.Add(s);
                    }

                    results.Add(new NetworkAdapterDnsInfo(
                        InterfaceIndex: ifIndex,
                        Name: name,
                        Description: desc,
                        Guid: guid,
                        Status: isUp ? "Up" : ni.OperationalStatus.ToString(),
                        IsVirtual: isVirtual,
                        IsWireless: isWireless,
                        Ipv4Servers: v4Servers,
                        Ipv4IsDhcp: v4IsDhcp,
                        Ipv6Servers: v6Servers,
                        Ipv6IsDhcp: v6IsDhcp,
                        HasDefaultGateway: hasGateway,
                        AdapterKind: kind));
                }
                catch
                {
                    // Skip broken individual adapter entry and continue scanning others
                }
            }
        }
        catch
        {
            // Fall through to return whatever was collected
        }

        return results
            .OrderByDescending(a => a.HasDefaultGateway)
            .ThenByDescending(a => !a.IsVirtual)
            .ThenByDescending(a => a.Status.Equals("Up", StringComparison.OrdinalIgnoreCase))
            .ThenBy(a => a.InterfaceIndex)
            .ToList();
    }

    private static (bool IsStatic, List<string> StaticServers) ReadRegistryDnsServers(string subKeyPath)
    {
        var servers = new List<string>();
        if (!OperatingSystem.IsWindows()) return (false, servers);
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: false);
            if (key is null) return (false, servers);

            string? nameServer = key.GetValue("NameServer") as string;
            if (!string.IsNullOrWhiteSpace(nameServer))
            {
                var parts = nameServer.Split([',', ';', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                foreach (var p in parts)
                {
                    if (IPAddress.TryParse(p, out var ip))
                    {
                        servers.Add(ip.ToString());
                    }
                }
                return (servers.Count > 0, servers);
            }
        }
        catch
        {
            // Registry read failure is non-fatal
        }

        return (false, servers);
    }

    private static async Task<IReadOnlyList<NetworkAdapterDnsInfo>> GetAdaptersPowerShellFallbackAsync(CancellationToken ct)
    {
        const string script = @"
$ProgressPreference = 'SilentlyContinue'
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
$result = @()
foreach ($a in $adapters) {
    $idx = $a.InterfaceIndex
    $alias = $a.Name
    $desc = $a.InterfaceDescription
    $guid = $a.InterfaceGuid

    $ipv4 = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $v4Servers = if ($ipv4) { @($ipv4.ServerAddresses) } else { @() }

    $ipv6 = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv6 -ErrorAction SilentlyContinue
    $v6Servers = if ($ipv6) { @($ipv6.ServerAddresses) } else { @() }

    $v4IsDhcp = $true
    try {
        $regV4 = Get-ItemProperty -Path ""HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"" -ErrorAction SilentlyContinue
        if ($regV4 -and $regV4.NameServer -and $regV4.NameServer.Trim().Length -gt 0) {
            $v4IsDhcp = $false
        }
    } catch {}

    $v6IsDhcp = $true
    try {
        $regV6 = Get-ItemProperty -Path ""HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid"" -ErrorAction SilentlyContinue
        if ($regV6 -and $regV6.NameServer -and $regV6.NameServer.Trim().Length -gt 0) {
            $v6IsDhcp = $false
        }
    } catch {}

    $isWireless = ($a.PhysicalMediaType -match 'Native 802.11' -or $a.MediaType -match 'Wireless' -or $a.NdisPhysicalMediaType -eq 9)

    $result += [PSCustomObject]@{
        InterfaceIndex = $idx
        Name = $alias
        Description = $desc
        Guid = $guid
        Status = [string]$a.Status
        IsVirtual = [bool]$a.Virtual
        IsWireless = [bool]$isWireless
        Ipv4Servers = $v4Servers
        Ipv4IsDhcp = $v4IsDhcp
        Ipv6Servers = $v6Servers
        Ipv6IsDhcp = $v6IsDhcp
    }
}
$result | ConvertTo-Json -Compress
";
        try
        {
            string output = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
            output = CleanJsonOutput(output);
            if (string.IsNullOrWhiteSpace(output)) return Array.Empty<NetworkAdapterDnsInfo>();

            List<NetworkAdapterDnsInfo> rawList;
            if (output.StartsWith('['))
            {
                rawList = JsonSerializer.Deserialize<List<NetworkAdapterDnsInfo>>(output) ?? new();
            }
            else
            {
                var single = JsonSerializer.Deserialize<NetworkAdapterDnsInfo>(output);
                rawList = single is not null ? new List<NetworkAdapterDnsInfo> { single } : new();
            }

            var normalized = new List<NetworkAdapterDnsInfo>();
            foreach (var item in rawList)
            {
                var (isNoise, isVirt, isWifi, kind) = ClassifyAdapter(
                    item.Name,
                    item.Description,
                    item.IsWireless ? NetworkInterfaceType.Wireless80211 : NetworkInterfaceType.Ethernet,
                    item.HasDefaultGateway,
                    item.IsVirtual);

                if (isNoise) continue;

                normalized.Add(item with
                {
                    IsVirtual = isVirt,
                    IsWireless = isWifi,
                    AdapterKind = kind
                });
            }

            return normalized;
        }
        catch
        {
            return Array.Empty<NetworkAdapterDnsInfo>();
        }
    }

    public async Task ApplyDnsAsync(IEnumerable<int> interfaceIndexes, bool onlyLocal, IReadOnlyList<AdapterDnsBackup> backups, CancellationToken ct = default)
    {
        var backupMap = backups.ToDictionary(b => b.InterfaceIndex);
        var targetList = interfaceIndexes.ToList();
        if (targetList.Count == 0) return;

        var psBuilder = new StringBuilder();
        psBuilder.AppendLine("$ProgressPreference = 'SilentlyContinue'");

        foreach (int idx in targetList)
        {
            var v4Servers = new List<string> { "127.0.0.1" };
            var v6Servers = new List<string>();

            if (backupMap.TryGetValue(idx, out var b))
            {
                if (!onlyLocal)
                {
                    foreach (var s in b.Ipv4Servers)
                    {
                        if (!s.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) && !v4Servers.Contains(s))
                            v4Servers.Add(s);
                    }
                }

                if (b.Ipv6Servers.Count > 0)
                {
                    v6Servers.Add("::1");
                    if (!onlyLocal)
                    {
                        foreach (var s in b.Ipv6Servers)
                        {
                            if (!s.Equals("::1", StringComparison.OrdinalIgnoreCase) && !v6Servers.Contains(s))
                                v6Servers.Add(s);
                        }
                    }
                }

                // Engine 1: Direct Registry update (works even if WMI/PowerShell is broken)
                TryWriteRegistryDnsServers(b.Guid, v4Servers, v6Servers);

                // Engine 2: netsh interface ipv4/ipv6 set dnsservers (WMI-independent)
                await TryApplyNetshDnsAsync(idx, b.Name, v4Servers, v6Servers, ct).ConfigureAwait(false);
            }

            var allServers = v4Servers.Concat(v6Servers).ToList();
            string serverList = string.Join(",", allServers.Select(s => $"'{s}'"));
            psBuilder.AppendLine($"Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses @({serverList}) -ErrorAction SilentlyContinue");
        }

        // Engine 3: Best-effort PowerShell Set-DnsClientServerAddress
        try
        {
            await RunPowerShellAsync(psBuilder.ToString(), ct).ConfigureAwait(false);
        }
        catch
        {
            // Registry + netsh already applied the DNS servers
        }

        // Engine 4: Flush Windows DNS cache immediately
        await TryFlushDnsCacheAsync(ct).ConfigureAwait(false);
    }

    public async Task RestoreDnsAsync(IReadOnlyList<AdapterDnsBackup> backups, CancellationToken ct = default)
    {
        if (backups.Count == 0) return;

        var psBuilder = new StringBuilder();
        psBuilder.AppendLine("$ProgressPreference = 'SilentlyContinue'");

        foreach (var b in backups)
        {
            // Engine 1: Direct Registry restore
            TryRestoreRegistryDnsServers(b);

            // Engine 2: netsh restore
            await TryRestoreNetshDnsAsync(b, ct).ConfigureAwait(false);

            // Engine 3: PowerShell Set-DnsClientServerAddress
            if (b.Ipv4IsDhcp && b.Ipv6IsDhcp)
            {
                psBuilder.AppendLine($"Set-DnsClientServerAddress -InterfaceIndex {b.InterfaceIndex} -ResetServerAddresses -ErrorAction SilentlyContinue");
            }
            else
            {
                var servers = b.Ipv4Servers.Concat(b.Ipv6Servers).ToList();
                if (servers.Count > 0)
                {
                    string serverList = string.Join(",", servers.Select(s => $"'{s}'"));
                    psBuilder.AppendLine($"Set-DnsClientServerAddress -InterfaceIndex {b.InterfaceIndex} -ServerAddresses @({serverList}) -ErrorAction SilentlyContinue");
                }
                else
                {
                    psBuilder.AppendLine($"Set-DnsClientServerAddress -InterfaceIndex {b.InterfaceIndex} -ResetServerAddresses -ErrorAction SilentlyContinue");
                }
            }
        }

        try
        {
            await RunPowerShellAsync(psBuilder.ToString(), ct).ConfigureAwait(false);
        }
        catch
        {
            // Registry + netsh already restored the DNS configuration
        }

        await TryFlushDnsCacheAsync(ct).ConfigureAwait(false);
    }

    private static void TryWriteRegistryDnsServers(string guid, IReadOnlyList<string> v4Servers, IReadOnlyList<string> v6Servers)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(guid)) return;

        try
        {
            using var keyV4 = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}", writable: true);
            keyV4?.SetValue("NameServer", string.Join(",", v4Servers), RegistryValueKind.String);
        }
        catch { }

        if (v6Servers.Count > 0)
        {
            try
            {
                using var keyV6 = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{guid}", writable: true);
                keyV6?.SetValue("NameServer", string.Join(",", v6Servers), RegistryValueKind.String);
            }
            catch { }
        }
    }

    private static void TryRestoreRegistryDnsServers(AdapterDnsBackup backup)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(backup.Guid)) return;

        try
        {
            using var keyV4 = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{backup.Guid}", writable: true);
            if (keyV4 is not null)
            {
                string val = backup.Ipv4IsDhcp ? "" : string.Join(",", backup.Ipv4Servers);
                keyV4.SetValue("NameServer", val, RegistryValueKind.String);
            }
        }
        catch { }

        try
        {
            using var keyV6 = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{backup.Guid}", writable: true);
            if (keyV6 is not null)
            {
                string val = backup.Ipv6IsDhcp ? "" : string.Join(",", backup.Ipv6Servers);
                keyV6.SetValue("NameServer", val, RegistryValueKind.String);
            }
        }
        catch { }
    }

    private static async Task TryApplyNetshDnsAsync(int idx, string adapterName, IReadOnlyList<string> v4Servers, IReadOnlyList<string> v6Servers, CancellationToken ct)
    {
        string target = !string.IsNullOrWhiteSpace(adapterName) ? adapterName : idx.ToString();

        if (v4Servers.Count > 0)
        {
            await RunCommandSilentAsync("netsh", ["interface", "ipv4", "set", "dnsservers", $"name={target}", "source=static", $"address={v4Servers[0]}", "register=primary", "validate=no"], ct).ConfigureAwait(false);
            for (int i = 1; i < v4Servers.Count; i++)
            {
                await RunCommandSilentAsync("netsh", ["interface", "ipv4", "add", "dnsservers", $"name={target}", $"address={v4Servers[i]}", $"index={i + 1}", "validate=no"], ct).ConfigureAwait(false);
            }
        }

        if (v6Servers.Count > 0)
        {
            await RunCommandSilentAsync("netsh", ["interface", "ipv6", "set", "dnsservers", $"name={target}", "source=static", $"address={v6Servers[0]}", "register=primary", "validate=no"], ct).ConfigureAwait(false);
            for (int i = 1; i < v6Servers.Count; i++)
            {
                await RunCommandSilentAsync("netsh", ["interface", "ipv6", "add", "dnsservers", $"name={target}", $"address={v6Servers[i]}", $"index={i + 1}", "validate=no"], ct).ConfigureAwait(false);
            }
        }
    }

    private static async Task TryRestoreNetshDnsAsync(AdapterDnsBackup b, CancellationToken ct)
    {
        string target = !string.IsNullOrWhiteSpace(b.Name) ? b.Name : b.InterfaceIndex.ToString();

        if (b.Ipv4IsDhcp || b.Ipv4Servers.Count == 0)
        {
            await RunCommandSilentAsync("netsh", ["interface", "ipv4", "set", "dnsservers", $"name={target}", "source=dhcp"], ct).ConfigureAwait(false);
        }
        else
        {
            await RunCommandSilentAsync("netsh", ["interface", "ipv4", "set", "dnsservers", $"name={target}", "source=static", $"address={b.Ipv4Servers[0]}", "register=primary", "validate=no"], ct).ConfigureAwait(false);
            for (int i = 1; i < b.Ipv4Servers.Count; i++)
            {
                await RunCommandSilentAsync("netsh", ["interface", "ipv4", "add", "dnsservers", $"name={target}", $"address={b.Ipv4Servers[i]}", $"index={i + 1}", "validate=no"], ct).ConfigureAwait(false);
            }
        }

        if (b.Ipv6IsDhcp || b.Ipv6Servers.Count == 0)
        {
            await RunCommandSilentAsync("netsh", ["interface", "ipv6", "set", "dnsservers", $"name={target}", "source=dhcp"], ct).ConfigureAwait(false);
        }
        else
        {
            await RunCommandSilentAsync("netsh", ["interface", "ipv6", "set", "dnsservers", $"name={target}", "source=static", $"address={b.Ipv6Servers[0]}", "register=primary", "validate=no"], ct).ConfigureAwait(false);
            for (int i = 1; i < b.Ipv6Servers.Count; i++)
            {
                await RunCommandSilentAsync("netsh", ["interface", "ipv6", "add", "dnsservers", $"name={target}", $"address={b.Ipv6Servers[i]}", $"index={i + 1}", "validate=no"], ct).ConfigureAwait(false);
            }
        }
    }

    private static Task TryFlushDnsCacheAsync(CancellationToken ct) =>
        RunCommandSilentAsync("ipconfig", ["/flushdns"], ct);

    private static async Task RunCommandSilentAsync(string fileName, IEnumerable<string> args, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo(fileName)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var proc = Process.Start(psi);
            if (proc is null) return;

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await proc.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch
        {
            // Non-fatal fallback command
        }
    }

    private static async Task<string> RunPowerShellAsync(string script, CancellationToken ct)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-EncodedCommand");
        psi.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start powershell.exe");
        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ProcessTimeout);

        try
        {
            await proc.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("The PowerShell network command timed out.");
        }

        string stdout = await stdoutTask.ConfigureAwait(false);
        string stderr = await stderrTask.ConfigureAwait(false);

        if (proc.ExitCode != 0 && !string.IsNullOrWhiteSpace(stderr))
        {
            throw new InvalidOperationException($"PowerShell command failed (exit code {proc.ExitCode}): {stderr.Trim()}");
        }

        return stdout;
    }

    private static string CleanJsonOutput(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";

        int startArray = raw.IndexOf('[');
        int startObj = raw.IndexOf('{');

        int start = -1;
        if (startArray >= 0 && startObj >= 0) start = Math.Min(startArray, startObj);
        else if (startArray >= 0) start = startArray;
        else if (startObj >= 0) start = startObj;

        if (start < 0) return "";

        int endArray = raw.LastIndexOf(']');
        int endObj = raw.LastIndexOf('}');
        int end = Math.Max(endArray, endObj);

        if (end < start) return "";
        return raw.Substring(start, end - start + 1);
    }
}
