namespace SpectraNetworkManager.Sinkhole;

/// <summary>Remembers answers from the upstream server until their TTL runs out (served with the remaining TTL).</summary>
public sealed class DnsCache
{
    private sealed record Entry(byte[] Response, DateTimeOffset Stored, DateTimeOffset Expires);

    private const uint MinTtl = 5;
    private const uint MaxTtl = 3600;
    private const uint DefaultNegativeTtl = 30;

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly object _lock = new();
    private readonly int _maxEntries;

    public DnsCache(int maxEntries = 10000) => _maxEntries = Math.Max(100, maxEntries);

    public int Count { get { lock (_lock) return _entries.Count; } }

    public static string Key(DnsQuestion q) => $"{q.Name}|{q.Type}|{q.Class}";

    public byte[]? TryGet(string key, ushort id, DateTimeOffset now)
    {
        lock (_lock)
        {
            if (!_entries.TryGetValue(key, out var e)) return null;
            if (now >= e.Expires)
            {
                _entries.Remove(key);
                return null;
            }

            uint remaining = (uint)Math.Max(1, Math.Ceiling((e.Expires - now).TotalSeconds));
            return DnsWire.Rewrite(e.Response, id, remaining);
        }
    }

    public void Put(string key, byte[] response, DateTimeOffset now)
    {
        int rcode = DnsWire.ResponseRcode(response);
        if (rcode is not (DnsRcode.NoError or DnsRcode.NxDomain) || DnsWire.IsTruncated(response)) return;

        uint ttl = DnsWire.MinTtl(response) ?? DefaultNegativeTtl;
        ttl = Math.Clamp(ttl, MinTtl, MaxTtl);

        lock (_lock)
        {
            if (_entries.Count >= _maxEntries) MakeRoom(now);
            _entries[key] = new Entry((byte[])response.Clone(), now, now.AddSeconds(ttl));
        }
    }

    public void Clear()
    {
        lock (_lock) _entries.Clear();
    }

    private void MakeRoom(DateTimeOffset now)
    {
        foreach (var k in _entries.Where(kv => now >= kv.Value.Expires).Select(kv => kv.Key).ToList()) _entries.Remove(k);
        if (_entries.Count < _maxEntries) return;

        // still full: drop the oldest tenth
        foreach (var k in _entries.OrderBy(kv => kv.Value.Stored).Take(Math.Max(1, _maxEntries / 10)).Select(kv => kv.Key).ToList())
            _entries.Remove(k);
    }
}
