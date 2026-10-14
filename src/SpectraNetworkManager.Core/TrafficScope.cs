namespace SpectraNetworkManager.Core;

public enum TrafficProtocol { Any = 0, Tcp = 1, Udp = 2 }

public enum ScopeMode
{
    /// <summary>Block all traffic of the program (in the chosen direction).</summary>
    Everything = 0,
    /// <summary>Block only traffic that matches the conditions.</summary>
    BlockMatching = 1,
    /// <summary>Allow only traffic that matches the conditions; block everything else.</summary>
    AllowOnly = 2,
}

/// <summary>
/// Which traffic of a program a block applies to. Ports mean the service port: the remote port for outgoing traffic,
/// the local port for incoming traffic. Addresses are always the other side's addresses.
/// </summary>
public sealed record TrafficScope(
    ScopeMode Mode = ScopeMode.Everything,
    TrafficProtocol Protocol = TrafficProtocol.Any,
    string Ports = "",
    string Addresses = "",
    bool KeepLocalNetwork = false)
{
    public static TrafficScope All { get; } = new();

    public bool IsEverything => Mode == ScopeMode.Everything;

    /// <summary>Returns true when the scope can be turned into firewall rules that really block something.</summary>
    public bool TryValidate(out string error)
    {
        error = "";
        if (IsEverything) return true;

        if (!PortSet.TryParse(Ports, out var ports, out error)) return false;
        if (!AddressSet.TryParse(Addresses, out var addresses, out error)) return false;

        if (Protocol == TrafficProtocol.Any && ports.IsEmpty && addresses.IsEmpty)
        {
            error = "Choose at least one condition (TCP or UDP, a port, or an address), or pick 'Block everything'.";
            return false;
        }

        if (Protocol == TrafficProtocol.Any && !ports.IsEmpty && Mode == ScopeMode.AllowOnly && ports.Complement().IsEmpty && addresses.IsEmpty)
        {
            error = "Those ports cover everything, so nothing would be blocked.";
            return false;
        }

        if (Mode == ScopeMode.AllowOnly && addresses.HasKeywords)
        {
            error = "'Allow only' works with IPv4 and IPv6 addresses, blocks and ranges. Windows keywords like LocalSubnet only work with 'Block only matching traffic'.";
            return false;
        }

        return true;
    }

    public string Describe()
    {
        if (IsEverything) return "everything";

        var parts = new List<string>();
        if (Protocol != TrafficProtocol.Any) parts.Add(Protocol.ToString().ToUpperInvariant());
        if (!string.IsNullOrWhiteSpace(Ports)) parts.Add("port " + Ports.Trim());
        if (!string.IsNullOrWhiteSpace(Addresses)) parts.Add("address " + Addresses.Trim());
        string what = parts.Count > 0 ? string.Join(", ", parts) : "?";

        return Mode == ScopeMode.AllowOnly
            ? $"ALLOW ONLY {what}{(KeepLocalNetwork ? " (+ local network)" : "")}"
            : $"only {what}";
    }
}
