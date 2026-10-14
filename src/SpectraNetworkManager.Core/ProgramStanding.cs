namespace SpectraNetworkManager.Core;

/// <summary>Everything we know about whether a program may use the network: your decision, its signature, and your trust list.</summary>
public sealed record ProgramStanding(ProgramRule? Rule, SignatureInfo? Signature, bool PublisherTrusted)
{
    /// <summary>A verified signature from a publisher you chose to trust.</summary>
    public bool IsTrusted => PublisherTrusted && Signature is { Status: SignatureStatus.Valid };

    /// <summary>Nothing left to ask: either you decided, or a trusted publisher vouches for it.</summary>
    public bool IsDecided => Rule is not null || IsTrusted;
}
