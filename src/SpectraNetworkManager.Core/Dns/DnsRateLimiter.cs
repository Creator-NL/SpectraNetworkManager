using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

namespace SpectraNetworkManager.Sinkhole;

/// <summary>
/// Provides per-client IP rate limiting (token bucket) and TCP connection concurrency limits
/// to safeguard the DNS sinkhole against amplification attacks, query floods, and connection exhaustion.
/// </summary>
public sealed class DnsRateLimiter
{
    private sealed class TokenBucket
    {
        public double Tokens;
        public long LastTimestamp;
    }

    private sealed class TcpLease : IDisposable
    {
        private readonly DnsRateLimiter _owner;
        private readonly IPAddress _address;
        private int _disposed;

        public TcpLease(DnsRateLimiter owner, IPAddress address)
        {
            _owner = owner;
            _address = address;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _owner.ReleaseTcp(_address);
            }
        }
    }

    private readonly ConcurrentDictionary<IPAddress, TokenBucket> _buckets = new();
    private readonly ConcurrentDictionary<IPAddress, int> _activeTcpByClient = new();
    private int _activeTcpTotal;
    private long _lastPruneTicks = Stopwatch.GetTimestamp();

    public DnsRateLimiter(int ratePerSecond = 50, int? burstCapacity = null, int maxTcpTotal = 64, int maxTcpPerClient = 8)
    {
        RatePerSecond = Math.Max(0, ratePerSecond);
        BurstCapacity = burstCapacity ?? Math.Max(100, RatePerSecond * 2);
        MaxTcpTotal = Math.Max(1, maxTcpTotal);
        MaxTcpPerClient = Math.Max(1, maxTcpPerClient);
    }

    public int RatePerSecond { get; }
    public int BurstCapacity { get; }
    public int MaxTcpTotal { get; }
    public int MaxTcpPerClient { get; }

    public int ActiveTcpConnections => Volatile.Read(ref _activeTcpTotal);

    /// <summary>
    /// Attempts to consume 1 query token for the client IP.
    /// Returns true if the query is permitted; false if rate limit is exceeded.
    /// </summary>
    public bool TryAcquireQuery(IPAddress clientAddress)
    {
        if (RatePerSecond <= 0) return true;

        if (clientAddress.IsIPv4MappedToIPv6)
            clientAddress = clientAddress.MapToIPv4();

        long now = Stopwatch.GetTimestamp();
        var bucket = _buckets.GetOrAdd(clientAddress, _ => new TokenBucket
        {
            Tokens = BurstCapacity,
            LastTimestamp = now,
        });

        lock (bucket)
        {
            double elapsedSeconds = (double)(now - bucket.LastTimestamp) / Stopwatch.Frequency;
            bucket.LastTimestamp = now;

            bucket.Tokens = Math.Min(BurstCapacity, bucket.Tokens + (elapsedSeconds * RatePerSecond));

            if (bucket.Tokens >= 1.0)
            {
                bucket.Tokens -= 1.0;
                MaybePrune(now);
                return true;
            }

            return false;
        }
    }

    /// <summary>
    /// Checks TCP concurrency limits. Returns true and an IDisposable lease if accepted, or false if rejected.
    /// </summary>
    public bool TryAcquireTcp(IPAddress clientAddress, out IDisposable? lease)
    {
        lease = null;

        if (clientAddress.IsIPv4MappedToIPv6)
            clientAddress = clientAddress.MapToIPv4();

        while (true)
        {
            int currentTotal = Volatile.Read(ref _activeTcpTotal);
            if (currentTotal >= MaxTcpTotal) return false;

            if (Interlocked.CompareExchange(ref _activeTcpTotal, currentTotal + 1, currentTotal) == currentTotal)
                break;
        }

        // Increment per-client count
        int perClient = _activeTcpByClient.AddOrUpdate(clientAddress, 1, (_, count) => count + 1);
        if (perClient > MaxTcpPerClient)
        {
            // Back out total and per-client
            Interlocked.Decrement(ref _activeTcpTotal);
            _activeTcpByClient.AddOrUpdate(clientAddress, 0, (_, count) => Math.Max(0, count - 1));
            return false;
        }

        lease = new TcpLease(this, clientAddress);
        return true;
    }

    private void ReleaseTcp(IPAddress clientAddress)
    {
        Interlocked.Decrement(ref _activeTcpTotal);
        _activeTcpByClient.AddOrUpdate(clientAddress, 0, (_, count) => Math.Max(0, count - 1));
    }

    private void MaybePrune(long now)
    {
        // Prune buckets that have been inactive for more than 2 minutes, every 60 seconds.
        long pruneIntervalTicks = Stopwatch.Frequency * 60;
        long last = Volatile.Read(ref _lastPruneTicks);
        if (now - last > pruneIntervalTicks)
        {
            if (Interlocked.CompareExchange(ref _lastPruneTicks, now, last) == last)
            {
                long thresholdTicks = Stopwatch.Frequency * 120;
                foreach (var pair in _buckets)
                {
                    if (now - pair.Value.LastTimestamp > thresholdTicks)
                        _buckets.TryRemove(pair.Key, out _);
                }
            }
        }
    }
}
