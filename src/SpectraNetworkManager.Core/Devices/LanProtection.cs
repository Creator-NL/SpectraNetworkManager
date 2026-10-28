using System.Net;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Core.Devices;

/// <summary>Windows network location types (NLM_NETWORK_CATEGORY).</summary>
public enum NetworkCategoryKind
{
    Public = 0,
    Private = 1,
    DomainAuthenticated = 2,
}

/// <summary>One network Windows is currently connected to (cable or Wi-Fi) and how Windows classifies it.</summary>
public sealed record NetworkProfileInfo(string Name, NetworkCategoryKind Category);

/// <summary>Overall state of "LAN protection" (other devices can use this PC as their DNS server).</summary>
public enum LanProtectionLevel
{
    /// <summary>DNS server is stopped or only reachable from this PC.</summary>
    Off,

    /// <summary>Listening on the LAN, but something is still missing (e.g. firewall rule).</summary>
    Partial,

    /// <summary>Listening on the LAN and the firewall is open.</summary>
    Active,
}

public sealed record LanProtectionStatus(
    LanProtectionLevel Level,
    string Headline,
    string Detail,
    IReadOnlyList<string> Warnings);

/// <summary>Pure rules for turning LAN protection on or off in a <see cref="DnsSettings"/> object.</summary>
public static class LanProtectionPlanner
{
    public const string LanAddress = "0.0.0.0";
    public const string LocalOnlyAddress = "127.0.0.1";

    /// <summary>Makes the DNS server listen on every interface. Other devices stay limited to the local network.</summary>
    public static void ApplyEnabled(DnsSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.ListenAddress = LanAddress;
        settings.RestrictClientsToLocalNetwork = true;
    }

    /// <summary>Goes back to listening on this PC only.</summary>
    public static void ApplyDisabled(DnsSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.ListenAddress = LocalOnlyAddress;
    }
}

/// <summary>
/// Works out the LAN protection state from what is <b>actually</b> happening (the bound socket, firewall rules,
/// companion server), not from what the settings file says.
/// </summary>
public static class LanProtectionEvaluator
{
    public static LanProtectionStatus Evaluate(
        IPEndPoint? dnsEndpoint,
        bool firewallOpen,
        bool companionRunning,
        IReadOnlyList<NetworkProfileInfo>? networks,
        string pcIp)
    {
        var warnings = new List<string>();

        if (dnsEndpoint is null)
        {
            return new LanProtectionStatus(
                LanProtectionLevel.Off,
                "LAN protection is OFF",
                "The DNS server is not running, so no other device can use it.",
                warnings);
        }

        if (IPAddress.IsLoopback(dnsEndpoint.Address))
        {
            return new LanProtectionStatus(
                LanProtectionLevel.Off,
                "LAN protection is OFF",
                $"The DNS server only listens on {dnsEndpoint.Address} (this PC). Phones and TVs cannot reach it.",
                warnings);
        }

        if (!firewallOpen)
        {
            return new LanProtectionStatus(
                LanProtectionLevel.Partial,
                "LAN protection is PARTIAL",
                $"Listening on {dnsEndpoint}, but the Windows Firewall rule is missing, so devices are blocked.",
                warnings);
        }

        if (networks is not null)
        {
            foreach (var net in networks.Where(n => n.Category == NetworkCategoryKind.Public))
            {
                warnings.Add($"Windows treats the network '{net.Name}' as Public. Spectra's firewall rules only apply to Private networks, so phones and TVs may be blocked.");
            }
        }

        if (!companionRunning)
        {
            warnings.Add("The mobile companion page (port 8765) is not running.");
        }

        return new LanProtectionStatus(
            LanProtectionLevel.Active,
            "LAN protection is ON",
            $"Listening on {dnsEndpoint} - set your device DNS to {pcIp} (and leave DNS 2 empty).",
            warnings);
    }
}

/// <summary>Decides whether a DNS log client string refers to a given device IP.</summary>
public static class DnsClientMatch
{
    /// <summary>Exact IP match. "192.168.1.7" must not match "192.168.1.70". A trailing ":port" is allowed.</summary>
    public static bool IsSameClient(string? clientText, string? ip)
    {
        if (string.IsNullOrWhiteSpace(clientText) || string.IsNullOrWhiteSpace(ip)) return false;

        string c = clientText.Trim();
        string target = ip.Trim();
        if (string.Equals(c, target, StringComparison.OrdinalIgnoreCase)) return true;

        // IPv4 with port: 192.168.1.7:5353
        int colon = c.LastIndexOf(':');
        if (colon > 0 && c.IndexOf(':', StringComparison.Ordinal) == colon)
        {
            return string.Equals(c[..colon], target, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }
}

/// <summary>Lets something happen only once per program run (for example the tray hint).</summary>
public sealed class OncePerRunGate
{
    private int _used;

    /// <summary>True the first time it is called, false every time after.</summary>
    public bool TryPass() => Interlocked.Exchange(ref _used, 1) == 0;
}

/// <summary>Computes which items to add or remove when a list (such as the Spectra AI process list) is kept in sync.</summary>
public static class ItemSyncPlanner
{
    /// <summary>
    /// Returns the keys to add (live but missing) and to remove (shown but gone).
    /// The protected key (the current selection) is never removed.
    /// </summary>
    public static (IReadOnlyList<int> Add, IReadOnlyList<int> Remove) Plan(
        IEnumerable<int> current,
        IEnumerable<int> live,
        int protectedKey)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(live);

        var currentSet = new HashSet<int>(current);
        var liveSet = new HashSet<int>(live);

        var add = live.Where(k => !currentSet.Contains(k)).Distinct().ToList();
        var remove = currentSet.Where(k => !liveSet.Contains(k) && k != protectedKey).ToList();
        return (add, remove);
    }
}
