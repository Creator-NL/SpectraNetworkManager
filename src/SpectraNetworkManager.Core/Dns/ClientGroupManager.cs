using System.Net;

namespace SpectraNetworkManager.Sinkhole;

/// <summary>
/// Evaluates DNS client requests against assigned Client Groups (e.g. Kids, IoT, Guest).
/// Matches clients by IP address or CIDR range and applies group-specific policies,
/// allow/block rules, and blocking toggles.
/// </summary>
public sealed class ClientGroupManager
{
    private sealed class GroupRule
    {
        public ClientGroup Group { get; }
        public List<IPAddress> SingleIps { get; } = new();
        public List<IPNetwork> Networks { get; } = new();
        public DomainFilter Filter { get; }

        public GroupRule(ClientGroup group, DomainFilter baseFilter)
        {
            Group = group;
            foreach (var r in group.ClientRanges)
            {
                string text = r.Trim();
                if (IPAddress.TryParse(text, out var ip))
                {
                    SingleIps.Add(ip);
                }
                else if (IPNetwork.TryParse(text, out var net))
                {
                    Networks.Add(net);
                }
            }

            // Build group domain filter if group defines custom rules
            if (group.CustomBlock.Count > 0 || group.CustomAllow.Count > 0)
            {
                Filter = baseFilter.WithOverrides(group.CustomBlock, group.CustomAllow);
            }
            else
            {
                Filter = baseFilter;
            }
        }

        public bool Matches(IPAddress clientIp)
        {
            if (SingleIps.Any(ip => ip.Equals(clientIp))) return true;
            if (Networks.Any(net => net.Contains(clientIp))) return true;
            return false;
        }
    }

    private readonly List<GroupRule> _groups = new();
    private readonly ClientGroup _defaultGroup;
    private readonly DomainFilter _baseFilter;

    public ClientGroupManager(IEnumerable<ClientGroup>? groups, DomainFilter baseFilter)
    {
        _baseFilter = baseFilter;
        _defaultGroup = new ClientGroup { Name = "Default", BlockingEnabled = true };

        if (groups is not null)
        {
            foreach (var g in groups)
            {
                if (g.Name.Equals("Default", StringComparison.OrdinalIgnoreCase))
                {
                    _defaultGroup = g;
                }
                else
                {
                    _groups.Add(new GroupRule(g, baseFilter));
                }
            }
        }
    }

    public (ClientGroup Group, DomainFilter Filter, bool BlockingEnabled) GetGroupForClient(IPAddress clientIp)
    {
        // Unmap IPv4-mapped IPv6 addresses if needed
        var targetIp = clientIp.IsIPv4MappedToIPv6 ? clientIp.MapToIPv4() : clientIp;

        foreach (var rule in _groups)
        {
            if (rule.Matches(targetIp))
            {
                return (rule.Group, rule.Filter, rule.Group.BlockingEnabled);
            }
        }

        return (_defaultGroup, _baseFilter, _defaultGroup.BlockingEnabled);
    }
}
