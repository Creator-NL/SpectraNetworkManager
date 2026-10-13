namespace NetSentinel.Core;

/// <summary>One Windows Firewall block rule to create. Ports are the remote port for outgoing rules and the local port for incoming rules.</summary>
public sealed record FirewallRuleSpec(string Label, RuleDirection Direction, TrafficProtocol Protocol, string? Ports, string? RemoteAddresses);

/// <summary>
/// Turns "block this program, in this direction, for this traffic" into the list of firewall block rules that implement it.
/// Windows Firewall lets a block override an allow, so "allow only X" is built as blocks for everything except X
/// (the complement of the allowed ports / addresses).
/// </summary>
public static class RulePlanner
{
    public static IReadOnlyList<FirewallRuleSpec> Plan(RuleDirection direction, TrafficScope? scope)
    {
        var directions = direction switch
        {
            RuleDirection.Outbound => new[] { RuleDirection.Outbound },
            RuleDirection.Inbound => new[] { RuleDirection.Inbound },
            _ => new[] { RuleDirection.Outbound, RuleDirection.Inbound },
        };

        var specs = new List<FirewallRuleSpec>();
        foreach (var d in directions) specs.AddRange(PlanOne(d, scope));
        return specs;
    }

    private static IEnumerable<FirewallRuleSpec> PlanOne(RuleDirection d, TrafficScope? scope)
    {
        string dir = d == RuleDirection.Outbound ? "out" : "in";

        if (scope is null || scope.IsEverything)
            return new[] { new FirewallRuleSpec(dir, d, TrafficProtocol.Any, null, null) };

        if (!scope.TryValidate(out string error)) throw new ArgumentException(error);
        PortSet.TryParse(scope.Ports, out var ports, out _);
        AddressSet.TryParse(scope.Addresses, out var addresses, out _);

        return scope.Mode == ScopeMode.BlockMatching
            ? PlanBlockMatching(d, dir, scope, ports, addresses)
            : PlanAllowOnly(d, dir, scope, ports, addresses);
    }

    private static IEnumerable<FirewallRuleSpec> PlanBlockMatching(RuleDirection d, string dir, TrafficScope scope, PortSet ports, AddressSet addresses)
    {
        string? portText = ports.IsEmpty ? null : ports.ToString();
        string? addressText = addresses.IsEmpty ? null : addresses.ToFirewallString();

        // Windows Firewall only accepts a port list together with a specific protocol.
        if (portText is not null && scope.Protocol == TrafficProtocol.Any)
        {
            yield return new FirewallRuleSpec($"{dir} tcp", d, TrafficProtocol.Tcp, portText, addressText);
            yield return new FirewallRuleSpec($"{dir} udp", d, TrafficProtocol.Udp, portText, addressText);
            yield break;
        }

        yield return new FirewallRuleSpec($"{dir} match", d, scope.Protocol, portText, addressText);
    }

    private static IEnumerable<FirewallRuleSpec> PlanAllowOnly(RuleDirection d, string dir, TrafficScope scope, PortSet ports, AddressSet addresses)
    {
        // When the local network stays reachable, "everything else" only means traffic to public addresses.
        string? publicOnly = scope.KeepLocalNetwork ? AddressSet.LocalNetwork.Complement().ToFirewallString() : null;

        // 1. Only one protocol allowed: block the other one.
        if (scope.Protocol != TrafficProtocol.Any)
        {
            var other = scope.Protocol == TrafficProtocol.Tcp ? TrafficProtocol.Udp : TrafficProtocol.Tcp;
            yield return new FirewallRuleSpec($"{dir} other-protocol", d, other, null, publicOnly);
        }

        // 2. Only some ports allowed: block all the other ports.
        if (!ports.IsEmpty)
        {
            var others = ports.Complement();
            if (!others.IsEmpty)
            {
                var protocols = scope.Protocol == TrafficProtocol.Any
                    ? new[] { TrafficProtocol.Tcp, TrafficProtocol.Udp }
                    : new[] { scope.Protocol };

                foreach (var p in protocols)
                    yield return new FirewallRuleSpec($"{dir} other-ports {p.ToString().ToLowerInvariant()}", d, p, others.ToString(), publicOnly);
            }
        }

        // 3. Only some addresses allowed: block all the other addresses (the local network stays allowed if requested).
        if (!addresses.IsEmpty)
        {
            var allowed = scope.KeepLocalNetwork ? addresses.Union(AddressSet.LocalNetwork) : addresses;
            var others = allowed.Complement();
            if (!others.IsEmpty)
                yield return new FirewallRuleSpec($"{dir} other-addresses", d, TrafficProtocol.Any, null, others.ToFirewallString());
        }
    }
}
