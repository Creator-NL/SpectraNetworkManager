namespace SpectraNetworkManager.Core;

public enum QuarantineStage
{
    PreCheck = 0,
    Stage1ProcessAndSockets = 1,
    Stage2WindowsService = 2,
    Stage3AutoStart = 3,
    Stage4FirewallBlock = 4,
    Complete = 5,
}

public sealed record QuarantineServiceRecord(
    string ServiceName,
    string DisplayName,
    uint OriginalStartType,
    bool WasRunning);

public sealed record QuarantineStartupRecord(
    string EntryId,
    string Name,
    string Location);

public sealed class QuarantineSnapshot
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string ExecutablePath { get; set; } = "";
    public string ProgramName { get; set; } = "";
    public DateTimeOffset QuarantinedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public RuleAction? PreviousRuleAction { get; set; }
    public List<int> TerminatedPids { get; set; } = new();
    public int ClosedSocketsCount { get; set; }
    public List<QuarantineServiceRecord> ModifiedServices { get; set; } = new();
    public List<QuarantineStartupRecord> DisabledStartupEntries { get; set; } = new();
    public bool FirewallRulesApplied { get; set; }
    public bool ExecutionLockoutApplied { get; set; }
    public string Reason { get; set; } = "";
    public bool IsRestored { get; set; }
    public DateTimeOffset? RestoredAtUtc { get; set; }

    public string SummaryDisplay
    {
        get
        {
            var parts = new List<string>();
            if (TerminatedPids.Count > 0) parts.Add($"Killed {TerminatedPids.Count} process{(TerminatedPids.Count > 1 ? "es" : "")}");
            if (ExecutionLockoutApplied) parts.Add("Execution Blocked (IFEO)");
            if (ClosedSocketsCount > 0) parts.Add($"Closed {ClosedSocketsCount} socket{(ClosedSocketsCount > 1 ? "s" : "")}");
            if (ModifiedServices.Count > 0) parts.Add($"Stopped {ModifiedServices.Count} service{(ModifiedServices.Count > 1 ? "s" : "")}");
            if (DisabledStartupEntries.Count > 0) parts.Add($"Disabled {DisabledStartupEntries.Count} auto-start{(DisabledStartupEntries.Count > 1 ? "s" : "")}");
            if (FirewallRulesApplied) parts.Add("Firewall Blocked");
            return parts.Count > 0 ? string.Join(", ", parts) : "Quarantined";
        }
    }

    public string StatusDisplay => IsRestored ? "Restored" : "Quarantined (Active)";
    public string ExecutionLockDisplay => ExecutionLockoutApplied ? "⛔ Locked (IFEO)" : (IsRestored ? "Allowed" : "Not Set");
    public string FirewallDisplay => FirewallRulesApplied ? "🧱 In + Out Block" : (IsRestored ? "Restored" : "None");
    public string QuarantinedAtDisplay => QuarantinedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
}
