namespace SpectraNetworkManager.Sinkhole;

/// <summary>
/// Routes queries for specific domain suffixes or reverse lookup zones (e.g. *.home, *.lan, 168.192.in-addr.arpa)
/// directly to a specific DNS server (such as your local router) instead of the public upstreams.
/// </summary>
public sealed record ConditionalForwardingRule(
    string DomainSuffix,
    string TargetServer,
    bool Enabled = true
);
