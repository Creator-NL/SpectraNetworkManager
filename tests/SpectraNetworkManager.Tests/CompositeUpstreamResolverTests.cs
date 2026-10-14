using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Tests;

public sealed class CompositeUpstreamResolverTests
{
    private sealed class MockResolver : IUpstreamResolver
    {
        public bool ShouldThrow { get; set; }
        public byte[]? AnswerToReturn { get; set; }
        public int CallCount { get; private set; }

        public Task<byte[]?> ResolveAsync(byte[] query, bool useTcp, CancellationToken ct)
        {
            CallCount++;
            if (ShouldThrow) throw new InvalidOperationException("Simulated network failure");
            return Task.FromResult(AnswerToReturn);
        }
    }

    [Fact]
    public async Task CompositeResolver_UsesPrimaryWhenHealthy()
    {
        var primaryMock = new MockResolver();
        var secondaryMock = new MockResolver();

        byte[] query = DnsWire.BuildQuery("example.com", DnsType.A, 0x1111);
        byte[] expected = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
        primaryMock.AnswerToReturn = expected;

        UpstreamEndpoint.TryParse("9.9.9.9", out var ep1);
        UpstreamEndpoint.TryParse("1.1.1.1", out var ep2);

        using var composite = new CompositeUpstreamResolver(new[]
        {
            (ep1!, (IUpstreamResolver)primaryMock),
            (ep2!, (IUpstreamResolver)secondaryMock)
        });

        var result = await composite.ResolveAsync(query, useTcp: false, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(expected, result);
        Assert.Equal(1, primaryMock.CallCount);
        Assert.Equal(0, secondaryMock.CallCount);

        var statuses = composite.GetStatuses();
        Assert.Equal(2, statuses.Count);
        Assert.True(statuses[0].IsHealthy);
        Assert.True(statuses[0].LastLatencyMs >= 0);
        Assert.Null(statuses[0].LastError);
    }

    [Fact]
    public async Task CompositeResolver_FallsBackToSecondaryOnFailure()
    {
        var primaryMock = new MockResolver { ShouldThrow = true };
        var secondaryMock = new MockResolver();

        byte[] query = DnsWire.BuildQuery("example.com", DnsType.A, 0x2222);
        byte[] expected = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120 };
        secondaryMock.AnswerToReturn = expected;

        UpstreamEndpoint.TryParse("https://9.9.9.9/dns-query", out var ep1);
        UpstreamEndpoint.TryParse("tls://1.1.1.1:853", out var ep2);

        using var composite = new CompositeUpstreamResolver(new[]
        {
            (ep1!, (IUpstreamResolver)primaryMock),
            (ep2!, (IUpstreamResolver)secondaryMock)
        });

        var result = await composite.ResolveAsync(query, useTcp: false, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(expected, result);
        Assert.Equal(1, primaryMock.CallCount);
        Assert.Equal(1, secondaryMock.CallCount);

        var statuses = composite.GetStatuses();
        Assert.Equal(2, statuses.Count);
        Assert.False(statuses[0].IsHealthy);
        Assert.Equal("Simulated network failure", statuses[0].LastError);
        Assert.True(statuses[1].IsHealthy);
    }
}
