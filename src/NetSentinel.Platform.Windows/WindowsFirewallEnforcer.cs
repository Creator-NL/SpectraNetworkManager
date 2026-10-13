using System.Collections;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using NetSentinel.Core;

namespace NetSentinel.Platform.Windows;

public sealed record ManagedFirewallRule(string Name, string? Program, string Direction, bool IsAllow = false, string? Service = null);

/// <summary>
/// Turns a "block this program" decision into real Windows Firewall rules (inbound + outbound), using the built-in
/// firewall COM API. Every rule it creates is tagged with the group "NetSentinel", so everything it ever did can be
/// listed or removed in one go (also visible in "Windows Defender Firewall with Advanced Security").
///
/// Needs Administrator. It never changes the firewall's default policy and never touches rules it did not create.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewallEnforcer
{
    public const string Group = "NetSentinel";

    private const int DirectionIn = 1;
    private const int DirectionOut = 2;
    private const int ActionBlock = 0;
    private const int ActionAllow = 1;
    private const int AllProfiles = 0x7FFFFFFF;
    private const int ProtocolTcp = 6;
    private const int ProtocolUdp = 17;

    /// <summary>
    /// Replaces whatever NetSentinel rules exist for this program with the planned block rules.
    /// If creating a rule fails half-way, the rules created so far are removed again, so a program is never left half-blocked.
    /// </summary>
    public void Block(string programPath, IReadOnlyList<FirewallRuleSpec> plan, string? note = null)
    {
        if (plan.Count == 0) throw new ArgumentException("The plan contains no rules, so nothing would be blocked.", nameof(plan));

        dynamic policy = Create("HNetCfg.FWPolicy2");
        RemoveForProgram(policy, programPath);

        var created = new List<string>();
        try
        {
            for (int i = 0; i < plan.Count; i++)
            {
                var spec = plan[i];
                string name = RuleName(programPath, spec.Label, i);

                dynamic rule = Create("HNetCfg.FWRule");
                rule.Name = name;
                rule.Description = note ?? "Blocked from NetSentinel. Remove it with NetSentinel, or delete the group 'NetSentinel' in Windows Firewall.";
                rule.ApplicationName = programPath;
                rule.Direction = spec.Direction == RuleDirection.Inbound ? DirectionIn : DirectionOut;
                rule.Action = ActionBlock;
                rule.Profiles = AllProfiles;
                rule.Grouping = Group;

                // The protocol has to be set before ports: Windows Firewall rejects ports on a rule that covers every protocol.
                if (spec.Protocol != TrafficProtocol.Any)
                    rule.Protocol = spec.Protocol == TrafficProtocol.Tcp ? ProtocolTcp : ProtocolUdp;

                if (spec.Ports is not null)
                {
                    // For incoming traffic the service port is the local port; for outgoing traffic it is the remote port.
                    if (spec.Direction == RuleDirection.Inbound) rule.LocalPorts = spec.Ports;
                    else rule.RemotePorts = spec.Ports;
                }

                if (spec.RemoteAddresses is not null) rule.RemoteAddresses = spec.RemoteAddresses;

                rule.Enabled = true;
                policy.Rules.Add(rule);
                created.Add(name);
            }
        }
        catch (Exception)
        {
            foreach (var name in created)
            {
                try { policy.Rules.Remove(name); } catch (Exception) { /* best effort */ }
            }
            throw;
        }
    }

    public void Unblock(string programPath)
    {
        dynamic policy = Create("HNetCfg.FWPolicy2");
        RemoveForProgram(policy, programPath);
    }

    /// <summary>How many NetSentinel firewall rules currently exist for each program path.</summary>
    public IReadOnlyDictionary<string, int> CountByProgram()
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in List())
        {
            if (rule.Program is null || rule.IsAllow) continue;     // allow rules belong to strict mode, not to a block
            counts[rule.Program] = counts.GetValueOrDefault(rule.Program) + 1;
        }
        return counts;
    }

    // Removes every NetSentinel rule of this program, whatever its name or scope (also rules made by older versions).
    private static void RemoveForProgram(dynamic policy, string programPath)
    {
        var names = new List<string>();
        foreach (dynamic rule in (IEnumerable)policy.Rules)
        {
            if ((string?)rule.Grouping != Group) continue;
            if (!string.Equals((string?)rule.ApplicationName, programPath, StringComparison.OrdinalIgnoreCase)) continue;
            names.Add((string)rule.Name);
        }

        foreach (var name in names) policy.Rules.Remove(name);
    }

    public IReadOnlyList<ManagedFirewallRule> List()
    {
        dynamic policy = Create("HNetCfg.FWPolicy2");
        var result = new List<ManagedFirewallRule>();
        foreach (dynamic rule in (IEnumerable)policy.Rules)
        {
            if ((string?)rule.Grouping != Group) continue;

            string? app = (string?)rule.ApplicationName;
            string? service = (string?)rule.ServiceName;
            result.Add(new ManagedFirewallRule(
                (string)rule.Name,
                string.IsNullOrEmpty(app) ? null : app,
                (int)rule.Direction == DirectionIn ? "in" : "out",
                IsAllow: (int)rule.Action == ActionAllow,
                Service: string.IsNullOrEmpty(service) ? null : service));
        }
        return result;
    }

    // ---- strict mode (block by default) ----------------------------------------------------

    private static readonly int[] ProfileTypes = { 1, 2, 4 };   // domain, private, public (NET_FW_PROFILE2_*)

    /// <summary>Reads the firewall's default action for outgoing connections (0 = block, 1 = allow) for every profile.</summary>
    public ProfileDefaults ReadDefaultOutbound()
    {
        object policy = Create("HNetCfg.FWPolicy2");
        return new ProfileDefaults(GetDefault(policy, 1), GetDefault(policy, 2), GetDefault(policy, 4));
    }

    /// <summary>
    /// Sets the default action for outgoing connections on all profiles and checks that Windows accepted it.
    /// If any profile cannot be set, the ones already changed are put back and an exception is thrown.
    /// </summary>
    public void SetDefaultOutbound(ProfileDefaults wanted)
    {
        object policy = Create("HNetCfg.FWPolicy2");
        var before = new ProfileDefaults(GetDefault(policy, 1), GetDefault(policy, 2), GetDefault(policy, 4));
        var targets = new[] { (1, wanted.Domain, before.Domain), (2, wanted.Private, before.Private), (4, wanted.Public, before.Public) };

        var changed = new List<(int Profile, int Old)>();
        try
        {
            foreach (var (profile, value, old) in targets)
            {
                if (value == old) continue;
                SetDefault(policy, profile, value);
                changed.Add((profile, old));

                if (GetDefault(policy, profile) != value)
                    throw new InvalidOperationException("Windows did not accept the new firewall default (it may be managed by a policy on this PC).");
            }
        }
        catch (Exception)
        {
            foreach (var (profile, old) in changed)
            {
                try { SetDefault(policy, profile, old); } catch (Exception) { /* best effort */ }
            }
            throw;
        }
    }

    private static int GetDefault(object policy, int profile) =>
        Convert.ToInt32(policy.GetType().InvokeMember("DefaultOutboundAction", BindingFlags.GetProperty, null, policy, new object[] { profile }));

    private static void SetDefault(object policy, int profile, int action) =>
        policy.GetType().InvokeMember("DefaultOutboundAction", BindingFlags.SetProperty, null, policy, new object[] { profile, action });

    /// <summary>Creates an outgoing ALLOW rule for a program (or service). Idempotent.</summary>
    public void Allow(AllowSpec spec)
    {
        if (spec.ProgramPath is null && spec.ServiceName is null)
            throw new ArgumentException("An allow rule needs a program or a service.", nameof(spec));

        dynamic policy = Create("HNetCfg.FWPolicy2");
        string name = AllowRuleName(spec);
        policy.Rules.Remove(name);

        dynamic rule = Create("HNetCfg.FWRule");
        rule.Name = name;
        rule.Description = "Allowed by NetSentinel strict mode. Removed when strict mode is switched off.";
        if (spec.ProgramPath is not null) rule.ApplicationName = spec.ProgramPath;
        if (spec.ServiceName is not null) rule.ServiceName = spec.ServiceName;
        rule.Direction = DirectionOut;
        rule.Action = ActionAllow;
        rule.Profiles = AllProfiles;
        rule.Grouping = Group;
        rule.Enabled = true;
        policy.Rules.Add(rule);
    }

    /// <summary>Removes the allow rules NetSentinel created for one program.</summary>
    public void RemoveAllow(string programPath)
    {
        dynamic policy = Create("HNetCfg.FWPolicy2");
        var names = new List<string>();
        foreach (dynamic rule in (IEnumerable)policy.Rules)
        {
            if ((string?)rule.Grouping != Group || (int)rule.Action != ActionAllow) continue;
            if (string.Equals((string?)rule.ApplicationName, programPath, StringComparison.OrdinalIgnoreCase)) names.Add((string)rule.Name);
        }
        foreach (var name in names) policy.Rules.Remove(name);
    }

    /// <summary>Removes every OUTGOING allow rule NetSentinel created for strict mode (block rules and the LAN DNS rules stay). Returns how many were removed.</summary>
    public int RemoveAllAllowRules()
    {
        dynamic policy = Create("HNetCfg.FWPolicy2");
        var names = new List<string>();
        foreach (dynamic rule in (IEnumerable)policy.Rules)
            if ((string?)rule.Grouping == Group && (int)rule.Action == ActionAllow && (int)rule.Direction == DirectionOut) names.Add((string)rule.Name);
        foreach (var name in names) policy.Rules.Remove(name);
        return names.Count;
    }

    // ---- DNS server for other devices on the home network ---------------------------------

    private const int ProfilesDomainAndPrivate = 3;     // never on "Public" networks (cafes, hotels)

    /// <summary>
    /// Lets other devices on your LOCAL network (not the internet) send DNS queries to NetSentinel: inbound TCP and UDP on the DNS port,
    /// only from the local subnet, only on Private and Domain networks.
    /// </summary>
    public void AllowInboundDns(string exePath, int port)
    {
        dynamic policy = Create("HNetCfg.FWPolicy2");
        RemoveInboundDns(exePath);

        foreach (var (protocol, label) in new[] { (ProtocolUdp, "udp"), (ProtocolTcp, "tcp") })
        {
            dynamic rule = Create("HNetCfg.FWRule");
            rule.Name = InboundDnsRuleName(exePath, label);
            rule.Description = "Lets devices on your local network use the NetSentinel DNS server. Removed from NetSentinel's DNS tab.";
            rule.ApplicationName = exePath;
            rule.Direction = DirectionIn;
            rule.Action = ActionAllow;
            rule.Protocol = protocol;
            rule.LocalPorts = port.ToString(System.Globalization.CultureInfo.InvariantCulture);
            rule.RemoteAddresses = "LocalSubnet";
            rule.Profiles = ProfilesDomainAndPrivate;
            rule.Grouping = Group;
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }
    }

    public void RemoveInboundDns(string exePath)
    {
        dynamic policy = Create("HNetCfg.FWPolicy2");
        var names = new List<string>();
        foreach (dynamic rule in (IEnumerable)policy.Rules)
        {
            if ((string?)rule.Grouping != Group || (int)rule.Action != ActionAllow || (int)rule.Direction != DirectionIn) continue;
            if (string.Equals((string?)rule.ApplicationName, exePath, StringComparison.OrdinalIgnoreCase)) names.Add((string)rule.Name);
        }
        foreach (var name in names) policy.Rules.Remove(name);
    }

    /// <summary>True if the inbound DNS rules for this program exist.</summary>
    public bool HasInboundDns(string exePath) =>
        List().Any(r => r.IsAllow && r.Direction == "in" && string.Equals(r.Program, exePath, StringComparison.OrdinalIgnoreCase));

    private static string InboundDnsRuleName(string exePath, string label)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(exePath.ToLowerInvariant()));
        return $"NetSentinel allow DNS server in ({label}) #{Convert.ToHexString(hash, 0, 4).ToLowerInvariant()}";
    }

    private static string AllowRuleName(AllowSpec spec)
    {
        string key = (spec.ProgramPath ?? "") + "|" + (spec.ServiceName ?? "");
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(key.ToLowerInvariant()));
        string shortHash = Convert.ToHexString(hash, 0, 4).ToLowerInvariant();
        string what = spec.ProgramPath is not null ? System.IO.Path.GetFileName(spec.ProgramPath) : "service " + spec.ServiceName;
        return $"NetSentinel allow {what} #{shortHash}";
    }

    /// <summary>Panic button: removes every rule NetSentinel created. Returns how many were removed.</summary>
    public int RemoveAll()
    {
        dynamic policy = Create("HNetCfg.FWPolicy2");
        var names = new List<string>();
        foreach (dynamic rule in (IEnumerable)policy.Rules)
            if ((string?)rule.Grouping == Group) names.Add((string)rule.Name);

        foreach (var name in names) policy.Rules.Remove(name);
        return names.Count;
    }

    private static object Create(string progId)
    {
        var type = Type.GetTypeFromProgID(progId) ?? throw new InvalidOperationException($"Windows Firewall component {progId} is not available.");
        return Activator.CreateInstance(type) ?? throw new InvalidOperationException($"Could not create {progId}.");
    }

    // Unique per program and rule: readable in the Windows Firewall UI, e.g. "NetSentinel block app.exe (out other-ports tcp) #3fa9c1d2-1"
    private static string RuleName(string programPath, string label, int index)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(programPath.ToLowerInvariant()));
        string shortHash = Convert.ToHexString(hash, 0, 4).ToLowerInvariant();
        return $"NetSentinel block {System.IO.Path.GetFileName(programPath)} ({label}) #{shortHash}-{index}";
    }
}
