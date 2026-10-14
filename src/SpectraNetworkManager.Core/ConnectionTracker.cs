using System.Net;

namespace SpectraNetworkManager.Core;

/// <summary>Identity of a connection across snapshots. State is deliberately excluded,
/// so SYN_SENT -> ESTABLISHED is the same connection, not a new one.</summary>
public readonly record struct ConnectionKey(Protocol Protocol, IPEndPoint Local, IPEndPoint? Remote, int ProcessId)
{
    public static ConnectionKey From(ConnectionInfo c) => new(c.Protocol, c.Local, c.Remote, c.ProcessId);
}

public sealed record ConnectionDiff(
    IReadOnlyList<ConnectionInfo> Opened,
    IReadOnlyList<ConnectionInfo> Closed);

/// <summary>
/// Compares consecutive snapshots and reports which connections appeared or disappeared.
/// This is the basis for the live log, alerts and (later) "new program wants to connect" prompts.
/// </summary>
public sealed class ConnectionTracker
{
    private Dictionary<ConnectionKey, ConnectionInfo> _known = new();
    private bool _primed;

    /// <param name="reportInitialAsOpened">If false, the very first snapshot only primes the tracker.</param>
    public ConnectionDiff Update(IReadOnlyList<ConnectionInfo> snapshot, bool reportInitialAsOpened = false)
    {
        var current = new Dictionary<ConnectionKey, ConnectionInfo>(snapshot.Count);
        foreach (var c in snapshot)
            current[ConnectionKey.From(c)] = c;

        var opened = new List<ConnectionInfo>();
        var closed = new List<ConnectionInfo>();

        if (_primed || reportInitialAsOpened)
        {
            foreach (var (key, conn) in current)
                if (!_known.ContainsKey(key)) opened.Add(conn);
        }

        foreach (var (key, conn) in _known)
            if (!current.ContainsKey(key)) closed.Add(conn);

        _known = current;
        _primed = true;
        return new ConnectionDiff(opened, closed);
    }
}
