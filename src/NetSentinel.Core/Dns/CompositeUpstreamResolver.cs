using System.Diagnostics;

namespace NetSentinel.Sinkhole;

/// <summary>
/// Composite upstream resolver that coordinates multiple upstreams (Standard UDP/TCP, DoH, DoT),
/// tracks per-upstream latency and health metrics, and performs automatic fallback.
/// </summary>
public sealed class CompositeUpstreamResolver : IUpstreamResolver, IDisposable
{
    private sealed class ResolverEntry : IDisposable
    {
        public UpstreamEndpoint Endpoint { get; }
        public IUpstreamResolver Resolver { get; }
        public bool IsHealthy { get; set; } = true;
        public int LastLatencyMs { get; set; } = -1;
        public DateTimeOffset LastChecked { get; set; } = DateTimeOffset.MinValue;
        public string? LastError { get; set; }

        public ResolverEntry(UpstreamEndpoint endpoint, IUpstreamResolver resolver)
        {
            Endpoint = endpoint;
            Resolver = resolver;
        }

        public void Dispose()
        {
            (Resolver as IDisposable)?.Dispose();
        }
    }

    private readonly List<ResolverEntry> _entries = new();
    private readonly object _lock = new();
    private bool _disposed;

    public CompositeUpstreamResolver(IEnumerable<UpstreamEndpoint> endpoints, TimeSpan? timeout = null, HttpMessageHandler? httpHandler = null)
    {
        foreach (var ep in endpoints)
        {
            var resolver = ep.CreateResolver(timeout, httpHandler);
            _entries.Add(new ResolverEntry(ep, resolver));
        }
    }

    public CompositeUpstreamResolver(IEnumerable<(UpstreamEndpoint Endpoint, IUpstreamResolver Resolver)> customEntries)
    {
        foreach (var (ep, resolver) in customEntries)
        {
            _entries.Add(new ResolverEntry(ep, resolver));
        }
    }

    public static CompositeUpstreamResolver FromStrings(IEnumerable<string> upstreams, TimeSpan? timeout = null, HttpMessageHandler? httpHandler = null)
    {
        var endpoints = new List<UpstreamEndpoint>();
        foreach (var text in upstreams)
        {
            if (UpstreamEndpoint.TryParse(text, out var ep))
            {
                endpoints.Add(ep);
            }
        }
        return new CompositeUpstreamResolver(endpoints, timeout, httpHandler);
    }

    public async Task<byte[]?> ResolveAsync(byte[] query, bool useTcp, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        List<ResolverEntry> snapshot;
        lock (_lock)
        {
            snapshot = _entries.ToList();
        }

        if (snapshot.Count == 0) return null;

        var sw = new Stopwatch();

        foreach (var entry in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            sw.Restart();

            try
            {
                byte[]? answer = await entry.Resolver.ResolveAsync(query, useTcp, ct).ConfigureAwait(false);
                sw.Stop();

                if (answer is not null)
                {
                    lock (_lock)
                    {
                        entry.IsHealthy = true;
                        entry.LastLatencyMs = (int)sw.ElapsedMilliseconds;
                        entry.LastChecked = DateTimeOffset.UtcNow;
                        entry.LastError = null;
                    }
                    return answer;
                }
                else
                {
                    lock (_lock)
                    {
                        entry.IsHealthy = false;
                        entry.LastLatencyMs = (int)sw.ElapsedMilliseconds;
                        entry.LastChecked = DateTimeOffset.UtcNow;
                        entry.LastError = "No answer returned";
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                sw.Stop();
                lock (_lock)
                {
                    entry.IsHealthy = false;
                    entry.LastLatencyMs = (int)sw.ElapsedMilliseconds;
                    entry.LastChecked = DateTimeOffset.UtcNow;
                    entry.LastError = ex.Message;
                }
            }
        }

        return null;
    }

    public IReadOnlyList<UpstreamStatus> GetStatuses()
    {
        lock (_lock)
        {
            return _entries.Select(e => new UpstreamStatus(
                e.Endpoint.OriginalText,
                e.Endpoint.DisplayName,
                e.Endpoint.Kind,
                e.IsHealthy,
                e.LastLatencyMs,
                e.LastChecked,
                e.LastError
            )).ToList();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        lock (_lock)
        {
            foreach (var entry in _entries)
            {
                entry.Dispose();
            }
            _entries.Clear();
        }
    }
}
