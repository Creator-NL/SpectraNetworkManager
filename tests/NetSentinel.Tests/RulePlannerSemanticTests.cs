using System.Net;
using NetSentinel.Core;

namespace NetSentinel.Tests;

public class RulePlannerSemanticTests
{
    private sealed record TestPacket(TrafficProtocol Protocol, int Port, IPAddress Address);

    [Fact]
    public void BlockMatching_SimpleEverything_CreatesSingleRule()
    {
        var rules = RulePlanner.Plan(RuleDirection.Outbound, TrafficScope.All);
        Assert.Single(rules);
        Assert.Equal(RuleDirection.Outbound, rules[0].Direction);
        Assert.Equal(TrafficProtocol.Any, rules[0].Protocol);
        Assert.Null(rules[0].Ports);
        Assert.Null(rules[0].RemoteAddresses);
    }

    [Fact]
    public void BlockMatching_BothDirections_CreatesInAndOutRules()
    {
        var rules = RulePlanner.Plan(RuleDirection.Both, TrafficScope.All);
        Assert.Equal(2, rules.Count);
        Assert.Contains(rules, r => r.Direction == RuleDirection.Outbound);
        Assert.Contains(rules, r => r.Direction == RuleDirection.Inbound);
    }

    [Fact]
    public void RandomisedSemanticTest_ZeroMismatches()
    {
        // Fixed seed so the test is completely deterministic and reproducible.
        var rnd = new Random(424242);

        var sampleAddresses = new[]
        {
            IPAddress.Parse("127.0.0.1"),      // loopback (LocalNetwork)
            IPAddress.Parse("192.168.1.10"),   // private (LocalNetwork)
            IPAddress.Parse("10.0.0.5"),       // private (LocalNetwork)
            IPAddress.Parse("8.8.8.8"),        // public
            IPAddress.Parse("1.1.1.1"),        // public
            IPAddress.Parse("93.184.216.34"),  // public (example.com)
            IPAddress.Parse("142.250.190.46"), // public
        };

        var samplePorts = new[] { 53, 80, 443, 8080, 12345 };
        var sampleProtocols = new[] { TrafficProtocol.Tcp, TrafficProtocol.Udp };

        for (int iteration = 0; iteration < 200; iteration++)
        {
            var mode = rnd.Next(2) == 0 ? ScopeMode.BlockMatching : ScopeMode.AllowOnly;
            var proto = (TrafficProtocol)rnd.Next(3); // Any, Tcp, Udp
            bool keepLocal = rnd.Next(2) == 0;

            string? portStr = rnd.Next(3) switch
            {
                0 => null,
                1 => "80, 443",
                _ => "1-1024, 8000-9000",
            };

            string? addrStr = rnd.Next(3) switch
            {
                0 => null,
                1 => "8.8.8.8, 1.1.1.1",
                _ => "192.168.0.0/16, 93.184.216.0/24",
            };

            var scope = new TrafficScope(mode, proto, portStr ?? "", addrStr ?? "", keepLocal);
            if (!scope.TryValidate(out _)) continue;

            PortSet.TryParse(scope.Ports, out var portSet, out _);
            AddressSet.TryParse(scope.Addresses, out var addrSet, out _);

            var plannedRules = RulePlanner.Plan(RuleDirection.Outbound, scope);

            // Pre-parse planned rule sets for fast evaluation
            var parsedRules = plannedRules.Select(r =>
            {
                PortSet.TryParse(r.Ports, out var p, out _);
                AddressSet.TryParse(r.RemoteAddresses, out var a, out _);
                return (r.Protocol, Ports: p, Addrs: a);
            }).ToList();

            foreach (var testProto in sampleProtocols)
            {
                foreach (var testPort in samplePorts)
                {
                    foreach (var testAddr in sampleAddresses)
                    {
                        var packet = new TestPacket(testProto, testPort, testAddr);

                        // 1. Semantic meaning
                        bool intendedBlocked;
                        if (scope.Mode == ScopeMode.BlockMatching)
                        {
                            bool protoMatches = scope.Protocol == TrafficProtocol.Any || scope.Protocol == packet.Protocol;
                            bool portMatches = portSet.IsEmpty || portSet.Contains(packet.Port);
                            bool addrMatches = addrSet.IsEmpty || addrSet.Contains(packet.Address);
                            intendedBlocked = protoMatches && portMatches && addrMatches;
                        }
                        else
                        {
                            // AllowOnly mode
                            bool localAllowed = scope.KeepLocalNetwork && AddressSet.LocalNetwork.Contains(packet.Address);
                            bool protoOk = scope.Protocol == TrafficProtocol.Any || scope.Protocol == packet.Protocol;
                            bool portOk = portSet.IsEmpty || portSet.Contains(packet.Port);
                            bool addrOk = addrSet.IsEmpty || addrSet.Contains(packet.Address);
                            bool specificAllowed = protoOk && portOk && addrOk;

                            intendedBlocked = !(localAllowed || specificAllowed);
                        }

                        // 2. Evaluation through planned firewall block rules (any matching block rule blocks the packet)
                        bool firewallBlocked = parsedRules.Any(rule =>
                        {
                            bool pMatch = rule.Protocol == TrafficProtocol.Any || rule.Protocol == packet.Protocol;
                            bool portMatch = rule.Ports.IsEmpty || rule.Ports.Contains(packet.Port);
                            bool addrMatch = rule.Addrs.IsEmpty || rule.Addrs.Contains(packet.Address);
                            return pMatch && portMatch && addrMatch;
                        });

                        Assert.True(intendedBlocked == firewallBlocked,
                            $"Iteration {iteration} mismatch for {scope}: Packet({packet.Protocol}, {packet.Port}, {packet.Address}) -> Intended blocked={intendedBlocked}, Firewall blocked={firewallBlocked}");
                    }
                }
            }
        }
    }
}
