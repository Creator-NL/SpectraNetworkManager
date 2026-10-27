namespace SpectraNetworkManager.Core.Ai;

public sealed record VerifiedProcessEvidence
{
    public int Pid { get; init; }
    public string ProcessName { get; init; } = "";
    public string? ExecutablePath { get; init; }
    public DateTimeOffset? ProcessStartTimeUtc { get; init; }
    public string? FileDescription { get; init; }
    public string? CompanyName { get; init; }
    public string? FileVersion { get; init; }
    public string? Sha256 { get; init; }
    public SignatureStatus SignatureStatus { get; init; } = SignatureStatus.Unknown;
    public string? Publisher { get; init; }
    public bool IsOsBinary { get; init; }
    public int? ParentPid { get; init; }
    public string? ParentProcessName { get; init; }
    public string? CommandLine { get; init; }
    public IReadOnlyList<string> Services { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> StartupEntries { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> ActiveConnections { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> RecentDnsQueries { get; init; } = Array.Empty<string>();
    public IReadOnlyList<int> ListeningPorts { get; init; } = Array.Empty<int>();
    public IdentityVerificationLevel VerificationLevel { get; init; } = IdentityVerificationLevel.UnsignedOrUnverified;
    public int DeterministicConfidenceScore { get; init; } = 50;
    public IReadOnlyList<string> SecurityFlags { get; init; } = Array.Empty<string>();

    public string FormatVerificationBadge() => VerificationLevel switch
    {
        IdentityVerificationLevel.VerifiedSystemBinary => "🛡️ Verified System Binary",
        IdentityVerificationLevel.VerifiedPublisherBinary => "✔ Verified Publisher",
        IdentityVerificationLevel.UnsignedOrUnverified => "⚠️ Unverified (Unsigned)",
        IdentityVerificationLevel.TamperedOrUntrusted => "🚨 Tampered / Invalid Signature",
        IdentityVerificationLevel.SuspiciousLocation => "⛔ Suspicious Location",
        IdentityVerificationLevel.EphemeralOrExited => "❓ Ephemeral / Exited",
        _ => "Unknown"
    };
}
