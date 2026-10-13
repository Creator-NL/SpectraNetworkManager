namespace NetSentinel.Core;

public enum RuleAction { Allow, Block }

/// <summary>Which traffic a block applies to. Both is the default, so older rule files keep working.</summary>
public enum RuleDirection { Both = 0, Outbound = 1, Inbound = 2 }

/// <summary>A decision about one program, identified by its full exe path.</summary>
public sealed record ProgramRule(
    string Path,
    RuleAction Action,
    DateTimeOffset Created,
    string? Note = null,
    RuleDirection Direction = RuleDirection.Both,
    TrafficScope? Scope = null)
{
    /// <summary>What a Block rule covers. Rules saved by older versions have no scope and mean "everything".</summary>
    public TrafficScope EffectiveScope => Scope ?? TrafficScope.All;

    public static string DescribeDirection(RuleDirection d) => d switch
    {
        RuleDirection.Outbound => "outgoing only",
        RuleDirection.Inbound => "incoming only",
        _ => "incoming + outgoing",
    };
}
