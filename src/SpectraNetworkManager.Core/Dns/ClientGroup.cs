namespace SpectraNetworkManager.Sinkhole;

/// <summary>
/// Allows assigning different filtering rules, block lists, and blocking toggles
/// to specific client devices or subnets based on IP address or CIDR range.
/// </summary>
public sealed class ClientGroup
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Name { get; set; } = "Default";
    public List<string> ClientRanges { get; set; } = new();
    public List<string> Blocklists { get; set; } = new();
    public List<string> CustomBlock { get; set; } = new();
    public List<string> CustomAllow { get; set; } = new();
    public bool BlockingEnabled { get; set; } = true;
    public BlockMode? BlockModeOverride { get; set; }
}
