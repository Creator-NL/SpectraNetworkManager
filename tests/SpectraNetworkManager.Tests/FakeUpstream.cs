using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Tests;

internal sealed class FakeUpstream : IUpstreamResolver
{
    public int CallCount;
    public Func<byte[], bool, byte[]?> Handler = (_, _) => null;

    public Task<byte[]?> ResolveAsync(byte[] query, bool useTcp, CancellationToken ct)
    {
        Interlocked.Increment(ref CallCount);
        return Task.FromResult(Handler(query, useTcp));
    }
}
