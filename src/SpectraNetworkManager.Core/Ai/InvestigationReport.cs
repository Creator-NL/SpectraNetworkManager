namespace SpectraNetworkManager.Core.Ai;

public enum ThreatVerdict
{
    Safe,
    LowRisk,
    Suspicious,
    Malicious,
    Unknown
}

public enum RecommendedAction
{
    Allow,
    Monitor,
    BlockFirewall,
    Quarantine
}

public sealed record InvestigationReport
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public string TargetType { get; init; } = "Process"; // "Process", "Connection", "Domain", "Port"
    public string TargetIdentifier { get; init; } = "";
    public int? Pid { get; init; }
    public string ProcessName { get; init; } = "";
    public IdentityVerificationLevel VerificationLevel { get; init; } = IdentityVerificationLevel.UnsignedOrUnverified;
    public ThreatVerdict Verdict { get; init; } = ThreatVerdict.Unknown;
    public int RiskScore { get; init; } = 50; // 0 (Clean) to 100 (Critical Malicious)
    public string ExecutiveSummary { get; init; } = "";
    public IReadOnlyList<string> KeyFindings { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> IdentifiedCapabilities { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Uncertainties { get; init; } = Array.Empty<string>();
    public RecommendedAction Recommendation { get; init; } = RecommendedAction.Monitor;
    public bool IsAiGenerated { get; init; }
    public string ModelUsed { get; init; } = "Deterministic Engine (Offline)";
    public VerifiedProcessEvidence? Evidence { get; init; }

    public string FormatVerdictBadge() => Verdict switch
    {
        ThreatVerdict.Safe => "🟢 SAFE",
        ThreatVerdict.LowRisk => "🔵 LOW RISK",
        ThreatVerdict.Suspicious => "🟡 SUSPICIOUS",
        ThreatVerdict.Malicious => "🔴 MALICIOUS",
        _ => "⚪ UNKNOWN"
    };

    public string FormatActionRecommendation() => Recommendation switch
    {
        RecommendedAction.Allow => "🛡️ Safe to Allow",
        RecommendedAction.Monitor => "👁️ Continue Monitoring",
        RecommendedAction.BlockFirewall => "🚫 Block Outbound Traffic",
        RecommendedAction.Quarantine => "⚠️ 4-Stage Quarantine",
        _ => "Investigate Further"
    };
}
