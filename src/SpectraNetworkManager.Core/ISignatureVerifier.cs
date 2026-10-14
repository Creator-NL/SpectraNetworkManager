namespace SpectraNetworkManager.Core;

/// <summary>
/// Verifies program signatures without ever blocking the caller.
/// TryGet returns the answer if it is already known; otherwise it returns null, starts the check in the background
/// and raises <see cref="Verified"/> (on a background thread) when the answer arrives.
/// </summary>
public interface ISignatureVerifier
{
    SignatureInfo? TryGet(string path);
    event Action<string, SignatureInfo>? Verified;
}
