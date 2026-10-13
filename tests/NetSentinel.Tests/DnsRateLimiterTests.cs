using System.Net;
using NetSentinel.Sinkhole;
using Xunit;

namespace NetSentinel.Tests;

public class DnsRateLimiterTests
{
    [Fact]
    public void RateLimiter_AllowsQueriesUpToBurstCapacity()
    {
        // 10 queries per second, burst 5
        var limiter = new DnsRateLimiter(ratePerSecond: 10, burstCapacity: 5);
        var client = IPAddress.Parse("192.168.1.100");

        for (int i = 0; i < 5; i++)
        {
            Assert.True(limiter.TryAcquireQuery(client), $"Query {i + 1} should be permitted within burst.");
        }

        // 6th query immediately should be rejected
        Assert.False(limiter.TryAcquireQuery(client), "Query exceeding burst should be rejected.");
    }

    [Fact]
    public void RateLimiter_DisabledWhenRateIsZero()
    {
        var limiter = new DnsRateLimiter(ratePerSecond: 0);
        var client = IPAddress.Parse("192.168.1.100");

        for (int i = 0; i < 1000; i++)
        {
            Assert.True(limiter.TryAcquireQuery(client));
        }
    }

    [Fact]
    public void RateLimiter_SeparateClientsHaveIndependentBuckets()
    {
        var limiter = new DnsRateLimiter(ratePerSecond: 10, burstCapacity: 2);
        var clientA = IPAddress.Parse("192.168.1.10");
        var clientB = IPAddress.Parse("192.168.1.20");

        Assert.True(limiter.TryAcquireQuery(clientA));
        Assert.True(limiter.TryAcquireQuery(clientA));
        Assert.False(limiter.TryAcquireQuery(clientA)); // Exhausted

        // Client B is unaffected
        Assert.True(limiter.TryAcquireQuery(clientB));
        Assert.True(limiter.TryAcquireQuery(clientB));
        Assert.False(limiter.TryAcquireQuery(clientB));
    }

    [Fact]
    public async Task RateLimiter_RefillsOverTime()
    {
        // 50 per sec, burst 2
        var limiter = new DnsRateLimiter(ratePerSecond: 50, burstCapacity: 2);
        var client = IPAddress.Parse("192.168.1.5");

        Assert.True(limiter.TryAcquireQuery(client));
        Assert.True(limiter.TryAcquireQuery(client));
        Assert.False(limiter.TryAcquireQuery(client));

        // Wait ~60ms (at 50/sec, 60ms = ~3 tokens, capped at burst 2)
        await Task.Delay(60);

        Assert.True(limiter.TryAcquireQuery(client), "Token should have refilled after delay.");
    }

    [Fact]
    public void TcpLimits_EnforcesTotalAndPerClientCaps()
    {
        var limiter = new DnsRateLimiter(maxTcpTotal: 4, maxTcpPerClient: 2);
        var clientA = IPAddress.Parse("10.0.0.1");
        var clientB = IPAddress.Parse("10.0.0.2");

        // Client A gets 2 connections
        Assert.True(limiter.TryAcquireTcp(clientA, out var leaseA1));
        Assert.True(limiter.TryAcquireTcp(clientA, out var leaseA2));
        Assert.False(limiter.TryAcquireTcp(clientA, out _), "Client A hit per-client limit of 2.");

        // Client B can still connect
        Assert.True(limiter.TryAcquireTcp(clientB, out var leaseB1));
        Assert.True(limiter.TryAcquireTcp(clientB, out var leaseB2));
        Assert.Equal(4, limiter.ActiveTcpConnections);

        // Now total limit of 4 is hit
        var clientC = IPAddress.Parse("10.0.0.3");
        Assert.False(limiter.TryAcquireTcp(clientC, out _), "Total limit of 4 reached.");

        // Release leaseA1
        leaseA1!.Dispose();
        Assert.Equal(3, limiter.ActiveTcpConnections);

        // Now Client A can connect again (down to 1 active)
        Assert.True(limiter.TryAcquireTcp(clientA, out var leaseA3));

        // Cleanup
        leaseA2!.Dispose();
        leaseA3!.Dispose();
        leaseB1!.Dispose();
        leaseB2!.Dispose();
        Assert.Equal(0, limiter.ActiveTcpConnections);
    }
}
