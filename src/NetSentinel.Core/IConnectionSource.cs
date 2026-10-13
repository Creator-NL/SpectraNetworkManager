namespace NetSentinel.Core;

/// <summary>
/// Anything that can produce a snapshot of the machine's network connections.
/// The Windows implementation lives in NetSentinel.Platform.Windows; tests can use fakes.
/// </summary>
public interface IConnectionSource
{
    IReadOnlyList<ConnectionInfo> GetConnections();
}

/// <summary>Resolves a process id to the program that owns it.</summary>
public interface IProcessResolver
{
    ProcessInfo Resolve(int pid);

    /// <summary>Forget cached entries for processes that are no longer running.</summary>
    void Prune(IReadOnlySet<int> alivePids);
}
