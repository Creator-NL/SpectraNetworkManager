using System.Net;

namespace SpectraNetworkManager.Core;

public enum Protocol { Tcp, Udp }

public enum ConnectionState
{
    /// <summary>UDP has no connection state.</summary>
    None = 0,
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12,
}

/// <summary>One TCP connection / listener or UDP endpoint at a point in time.</summary>
public sealed record ConnectionInfo(
    Protocol Protocol,
    IPEndPoint Local,
    IPEndPoint? Remote,
    ConnectionState State,
    int ProcessId);

/// <summary>Deterministic verification level of a process identity based on OS facts and Authenticode signature.</summary>
public enum IdentityVerificationLevel
{
    Unknown = 0,
    VerifiedSystemBinary = 1,
    VerifiedPublisherBinary = 2,
    UnsignedOrUnverified = 3,
    TamperedOrUntrusted = 4,
}

/// <summary>The program that owns a connection, enriched with parent process, command-line, start time, and Windows service metadata.</summary>
public sealed record ProcessInfo(
    int Pid,
    string Name,
    string? Path,
    int? ParentPid = null,
    string? ParentName = null,
    string? CommandLine = null,
    DateTimeOffset? StartTimeUtc = null,
    string? ServiceNames = null)
{
    public static IdentityVerificationLevel ClassifyIdentity(string? path, SignatureInfo? signature)
    {
        if (signature is { IsAlarming: true })
            return IdentityVerificationLevel.TamperedOrUntrusted;

        if (signature is { Status: SignatureStatus.Valid, IsOsBinary: true })
            return IdentityVerificationLevel.VerifiedSystemBinary;

        if (signature is { Status: SignatureStatus.Valid })
            return IdentityVerificationLevel.VerifiedPublisherBinary;

        if (!string.IsNullOrWhiteSpace(path))
            return IdentityVerificationLevel.UnsignedOrUnverified;

        return IdentityVerificationLevel.Unknown;
    }

    public static IdentityVerificationLevel ClassifyIdentity(SignatureInfo? signature, string? path) =>
        ClassifyIdentity(path, signature);

    public static string DescribeIdentityLevel(IdentityVerificationLevel level, SignatureInfo? signature = null) => level switch
    {
        IdentityVerificationLevel.VerifiedSystemBinary => "✔ VERIFIED WINDOWS OS BINARY",
        IdentityVerificationLevel.VerifiedPublisherBinary => $"✔ VERIFIED PUBLISHER ({signature?.Publisher ?? "Signed"})",
        IdentityVerificationLevel.TamperedOrUntrusted => "🚨 WARNING: TAMPERED / UNTRUSTED SIGNATURE",
        IdentityVerificationLevel.UnsignedOrUnverified => "⚠ UNSIGNED / UNVERIFIED EXECUTABLE",
        _ => "? UNKNOWN / EPHEMERAL PROCESS"
    };
}

/// <summary>A connection together with its resolved owner, ready for display.</summary>
public sealed record ConnectionView(ConnectionInfo Connection, ProcessInfo Process);
