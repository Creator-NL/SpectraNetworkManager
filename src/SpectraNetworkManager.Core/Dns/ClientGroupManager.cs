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
        private DomainFilter? _cachedFilter;
        private DomainFilter? _lastBaseFilter;

        public GroupRule(ClientGroup group)
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
        }

        public DomainFilter GetFilter(DomainFilter baseFilter)
        {
            if (Group.CustomBlock.Count == 0 && Group.CustomAllow.Count == 0)
                return baseFilter;

            if (_cachedFilter is not null && ReferenceEquals(_lastBaseFilter, baseFilter))
                return _cachedFilter;

            _lastBaseFilter = baseFilter;
            _cachedFilter = baseFilter.WithOverrides(Group.CustomBlock, Group.CustomAllow);
            return _cachedFilter;
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
    private readonly Func<DomainFilter> _baseFilterProvider;

    public ClientGroupManager(IEnumerable<ClientGroup>? groups, Func<DomainFilter> baseFilterProvider)
    {
        _baseFilterProvider = baseFilterProvider;
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
                    _groups.Add(new GroupRule(g));
                }
            }
        }
    }

    public ClientGroupManager(IEnumerable<ClientGroup>? groups, DomainFilter baseFilter)
        : this(groups, () => baseFilter)
    {
    }

    public (ClientGroup Group, DomainFilter Filter, bool BlockingEnabled) GetGroupForClient(IPAddress clientIp)
    {
        // Unmap IPv4-mapped IPv6 addresses if needed
        var targetIp = clientIp.IsIPv4MappedToIPv6 ? clientIp.MapToIPv4() : clientIp;
        var baseFilter = _baseFilterProvider();

        foreach (var rule in _groups)
        {
            if (rule.Matches(targetIp))
            {
                return (rule.Group, rule.GetFilter(baseFilter), rule.Group.BlockingEnabled);
            }
        }

        return (_defaultGroup, baseFilter, _defaultGroup.BlockingEnabled);
    }
}
