using System.Collections.Concurrent;

namespace NetSentinel.Sinkhole;

public enum DnsOutcome { Forwarded, Cached, Blocked, Failed, Refused }

public sealed record DnsLogEntry(DateTimeOffset Time, string Client, string Domain, string Type, DnsOutcome Outcome, string? Detail, int Milliseconds);

public sealed record DnsStats(
    long Total, long Blocked, long Cached, long Forwarded, long Failed,
    int UniqueDomains,
    IReadOnlyList<KeyValuePair<string, int>> TopBlocked,
    IReadOnlyList<KeyValuePair<string, int>> TopQueried,
    IReadOnlyList<KeyValuePair<string, int>> TopClients)
{
    public double BlockedPercent => Total == 0 ? 0 : 100.0 * Blocked / Total;
}

/// <summary>The recent query log (a bounded ring) and running statistics.</summary>
public sealed class DnsActivity
{
    private const int MaxLog = 5000;
    private const int MaxDistinct = 50000;

    private readonly LinkedList<DnsLogEntry> _recent = new();
    private readonly object _lock = new();
    private readonly ConcurrentDictionary<string, int> _queried = new();
    private readonly ConcurrentDictionary<string, int> _blocked = new();
    private readonly ConcurrentDictionary<string, int> _clients = new();
    private long _total, _blockedCount, _cached, _forwarded, _failed;

    public void Add(DnsLogEntry e)
    {
        lock (_lock)
        {
            _recent.AddFirst(e);
            while (_recent.Count > MaxLog) _recent.RemoveLast();
        }

        Interlocked.Increment(ref _total);
        switch (e.Outcome)
        {
            case DnsOutcome.Blocked: Interlocked.Increment(ref _blockedCount); Count(_blocked, e.Domain); break;
            case DnsOutcome.Cached: Interlocked.Increment(ref _cached); break;
            case DnsOutcome.Forwarded: Interlocked.Increment(ref _forwarded); break;
            default: Interlocked.Increment(ref _failed); break;
        }
        Count(_queried, e.Domain);
        Count(_clients, e.Client);
    }

    private static void Count(ConcurrentDictionary<string, int> map, string key)
    {
        if (map.Count >= MaxDistinct && !map.ContainsKey(key)) return;      // bounded memory
        map.AddOrUpdate(key, 1, (_, n) => n + 1);
    }

    public IReadOnlyList<DnsLogEntry> Recent(int max = 500)
    {
        lock (_lock) return _recent.Take(max).ToList();
    }

    public DnsStats Snapshot() => new(
        Interlocked.Read(ref _total), Interlocked.Read(ref _blockedCount), Interlocked.Read(ref _cached),
        Interlocked.Read(ref _forwarded), Interlocked.Read(ref _failed),
        _queried.Count, Top(_blocked), Top(_queried), Top(_clients));

    private static IReadOnlyList<KeyValuePair<string, int>> Top(ConcurrentDictionary<string, int> map, int n = 10) =>
        map.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal).Take(n).ToList();

    public void Reset()
    {
        lock (_lock) _recent.Clear();
        _queried.Clear(); _blocked.Clear(); _clients.Clear();
        Interlocked.Exchange(ref _total, 0); Interlocked.Exchange(ref _blockedCount, 0); Interlocked.Exchange(ref _cached, 0);
        Interlocked.Exchange(ref _forwarded, 0); Interlocked.Exchange(ref _failed, 0);
    }
}
