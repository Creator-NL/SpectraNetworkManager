using System.Net;

namespace SpectraNetworkManager.Core;

/// <summary>Result of one polling cycle: the full current picture plus what changed since last time.</summary>
public sealed record MonitorTick(
    DateTimeOffset Time,
    IReadOnlyList<ConnectionView> Connections,
    IReadOnlyList<ConnectionView> Opened,
    IReadOnlyList<ConnectionView> Closed);

/// <summary>
/// Polls an <see cref="IConnectionSource"/>, resolves owning programs and works out what opened/closed.
/// UI-agnostic: the WPF app, the console spike and (later) the engine service all use this same class.
/// </summary>
public sealed class ConnectionMonitor
{
    private readonly IConnectionSource _source;
    private readonly IProcessResolver _resolver;
    private readonly ConnectionTracker _tracker = new();
    private readonly Dictionary<(Protocol Protocol, IPEndPoint Local, IPEndPoint? Remote), (ProcessInfo Process, DateTimeOffset LastSeen)> _socketOwners = new();

    public ConnectionMonitor(IConnectionSource source, IProcessResolver resolver)
    {
        _source = source;
        _resolver = resolver;
    }

    public IProcessResolver Resolver => _resolver;

    public MonitorTick Poll()
    {
        var now = DateTimeOffset.Now;
        var snapshot = _source.GetConnections();

        // First record all active (PID > 0) socket owners so sockets transitioning to TIME_WAIT (PID 0) keep their owning program
        foreach (var c in snapshot)
        {
            if (c.ProcessId > 0)
            {
                var proc = _resolver.Resolve(c.ProcessId);
                _socketOwners[(c.Protocol, c.Local, c.Remote)] = (proc, now);
            }
        }

        // Normalize snapshot so PID 0 sockets that were previously owned by a known process retain their owner
        var normalizedSnapshot = new List<ConnectionInfo>(snapshot.Count);
        foreach (var c in snapshot)
        {
            if (c.ProcessId == 0 && _socketOwners.TryGetValue((c.Protocol, c.Local, c.Remote), out var known))
            {
                normalizedSnapshot.Add(c with { ProcessId = known.Process.Pid });
            }
            else
            {
                normalizedSnapshot.Add(c);
            }
        }

        var diff = _tracker.Update(normalizedSnapshot);

        // Resolve everything (including just-closed connections) BEFORE pruning,
        // so a closed connection still shows the program name from the cache.
        var connections = normalizedSnapshot.Select(c => ToView(c, now)).ToList();
        var opened = diff.Opened.Select(c => ToView(c, now)).ToList();
        var closed = diff.Closed.Select(c => ToView(c, now)).ToList();

        var alivePids = normalizedSnapshot.Select(c => c.ProcessId).ToHashSet();
        _resolver.Prune(alivePids);

        // Prune socket owner cache entries older than 3 minutes
        var cutoff = now.AddMinutes(-3);
        foreach (var key in _socketOwners.Where(kv => kv.Value.LastSeen < cutoff).Select(kv => kv.Key).ToList())
        {
            _socketOwners.Remove(key);
        }

        return new MonitorTick(now, connections, opened, closed);
    }

    private ConnectionView ToView(ConnectionInfo c, DateTimeOffset now)
    {
        if (_socketOwners.TryGetValue((c.Protocol, c.Local, c.Remote), out var known) &&
            (c.ProcessId == 0 || c.ProcessId == known.Process.Pid))
        {
            _socketOwners[(c.Protocol, c.Local, c.Remote)] = (known.Process, now);
            return new ConnectionView(c, known.Process);
        }

        return new ConnectionView(c, _resolver.Resolve(c.ProcessId));
    }
}
