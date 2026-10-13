using System.Collections.Concurrent;
using System.Net;

namespace NetSentinel.Core;

/// <summary>
/// Looks up host names for remote IP addresses in the background and remembers the answers.
/// Never blocks the caller: Request() returns what is known right now and the Resolved event fires when a lookup finishes.
/// Note: reverse lookups are DNS queries, so they are visible to whatever DNS server the PC uses.
/// </summary>
public sealed class ReverseDnsCache
{
    private readonly ConcurrentDictionary<IPAddress, string?> _results = new();
    private readonly ConcurrentDictionary<IPAddress, byte> _inFlight = new();
    private readonly SemaphoreSlim _gate = new(8);
    private readonly Func<IPAddress, CancellationToken, Task<string?>> _lookup;
    private readonly TimeSpan _timeout;

    public ReverseDnsCache(Func<IPAddress, CancellationToken, Task<string?>>? lookup = null, TimeSpan? timeout = null)
    {
        _lookup = lookup ?? DefaultLookupAsync;
        _timeout = timeout ?? TimeSpan.FromSeconds(3);
    }

    /// <summary>Raised on a thread-pool thread when a lookup completes (name is null if none was found).</summary>
    public event Action<IPAddress, string?>? Resolved;

    public string? Request(IPAddress ip)
    {
        if (Display.IsLocalAddress(ip) && (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)))
            return null;

        if (_results.TryGetValue(ip, out var known)) return known;
        if (_inFlight.TryAdd(ip, 0)) _ = Task.Run(() => ResolveAsync(ip));
        return null;
    }

    private async Task ResolveAsync(IPAddress ip)
    {
        string? name = null;
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            using var cts = new CancellationTokenSource(_timeout);
            name = await _lookup(ip, cts.Token).WaitAsync(_timeout).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // timeout, NXDOMAIN, network down: remember "no name" so we don't ask again and again
        }
        finally
        {
            _gate.Release();
        }

        _results[ip] = name;
        _inFlight.TryRemove(ip, out _);
        Resolved?.Invoke(ip, name);
    }

    private static async Task<string?> DefaultLookupAsync(IPAddress ip, CancellationToken ct)
    {
        var entry = await Dns.GetHostEntryAsync(ip).ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(entry.HostName) || entry.HostName == ip.ToString() ? null : entry.HostName;
    }
}
