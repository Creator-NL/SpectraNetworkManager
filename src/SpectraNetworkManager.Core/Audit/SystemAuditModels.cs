namespace SpectraNetworkManager.Core.Audit;

public enum AuditSeverity
{
    Good,
    Info,
    Warning,
    Critical
}

public sealed record AuditFinding(
    string Id,
    AuditSeverity Severity,
    string Category,
    string Title,
    string Description,
    string Recommendation,
    string? FixActionLabel = null,
    string? TargetTab = null,
    bool CanAutoFix = false)
{
    public string SeverityBadge => Severity switch
    {
        AuditSeverity.Good => "✅ OK",
        AuditSeverity.Info => "ℹ️ INFO",
        AuditSeverity.Warning => "⚠️ WARNING",
        AuditSeverity.Critical => "🚨 CRITICAL",
        _ => "•"
    };

    public string SeverityColor => Severity switch
    {
        AuditSeverity.Good => "#00FF88",
        AuditSeverity.Info => "#22E8FF",
        AuditSeverity.Warning => "#FFB020",
        AuditSeverity.Critical => "#FF2BD6",
        _ => "#D7E3FF"
    };
}

public sealed record SystemAuditReport(
    DateTime AuditTimeUtc,
    int TotalChecks,
    int GoodCount,
    int WarningCount,
    int CriticalCount,
    IReadOnlyList<AuditFinding> Findings)
{
    public int HealthScore => TotalChecks > 0
        ? Math.Max(0, 100 - (CriticalCount * 25) - (WarningCount * 10))
        : 100;

    public string HealthRating => HealthScore switch
    {
        >= 90 => "🛡️ EXCELLENT",
        >= 70 => "🟡 GOOD (Minor Actions Needed)",
        >= 50 => "🟠 ATTENTION REQUIRED",
        _ => "🚨 VULNERABLE"
    };
}
