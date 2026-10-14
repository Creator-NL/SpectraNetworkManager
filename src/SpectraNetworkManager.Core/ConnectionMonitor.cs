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

    public ConnectionMonitor(IConnectionSource source, IProcessResolver resolver)
    {
        _source = source;
        _resolver = resolver;
    }

    public IProcessResolver Resolver => _resolver;

    public MonitorTick Poll()
    {
        var snapshot = _source.GetConnections();
        var diff = _tracker.Update(snapshot);

        // Resolve everything (including just-closed connections) BEFORE pruning,
        // so a closed connection still shows the program name from the cache.
        var connections = snapshot.Select(ToView).ToList();
        var opened = diff.Opened.Select(ToView).ToList();
        var closed = diff.Closed.Select(ToView).ToList();

        _resolver.Prune(snapshot.Select(c => c.ProcessId).ToHashSet());
        return new MonitorTick(DateTimeOffset.Now, connections, opened, closed);
    }

    private ConnectionView ToView(ConnectionInfo c) => new(c, _resolver.Resolve(c.ProcessId));
}
