namespace SpectraNetworkManager.Core;

public enum SignatureStatus
{
    /// <summary>Could not be checked (yet, or the check failed). Never treated as good or bad.</summary>
    Unknown = 0,
    /// <summary>A valid digital signature: the file is unchanged since it was signed and the certificate chains to a trusted root.</summary>
    Valid,
    NotSigned,
    /// <summary>Signed, but the certificate is not trusted by Windows.</summary>
    Untrusted,
    /// <summary>Signed, but the file no longer matches its signature: it was modified after signing.</summary>
    Tampered,
}

/// <param name="Publisher">Common name of the signing certificate, e.g. "Microsoft Corporation".</param>
/// <param name="IsOsBinary">Signed as part of Windows itself.</param>
public sealed record SignatureInfo(SignatureStatus Status, string? Publisher, bool IsOsBinary, string? Detail = null)
{
    public bool IsValid => Status == SignatureStatus.Valid;

    /// <summary>Short text for a table cell.</summary>
    public string Describe() => Status switch
    {
        SignatureStatus.Valid => "\u2714 " + (Publisher ?? "signed") + (IsOsBinary ? " (Windows)" : ""),
        SignatureStatus.NotSigned => "not signed",
        SignatureStatus.Untrusted => "\u2718 untrusted signature" + (Publisher is null ? "" : $" ({Publisher})"),
        SignatureStatus.Tampered => "\u2718 SIGNATURE BROKEN - file was modified",
        _ => "unknown",
    };

    /// <summary>True when the signature is a reason to be careful, not just "nobody vouches for this".</summary>
    public bool IsAlarming => Status is SignatureStatus.Tampered or SignatureStatus.Untrusted;
}
