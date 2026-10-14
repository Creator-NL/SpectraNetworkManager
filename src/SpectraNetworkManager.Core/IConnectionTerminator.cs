using System.Net;

namespace SpectraNetworkManager.Core;

/// <summary>
/// Provides capabilities to terminate active network connections or running processes.
/// </summary>
public interface IConnectionTerminator
{
    /// <summary>
    /// Terminates all open IPv4 TCP connections owned by the specified process ID.
    /// Returns the number of connections successfully terminated.
    /// </summary>
    int TerminateConnectionsForPid(int pid);

    /// <summary>
    /// Terminates all open IPv4 TCP connections owned by processes running the specified executable path or file name.
    /// Returns the number of connections successfully terminated.
    /// </summary>
    int TerminateConnectionsForProgram(string pathOrName);

    /// <summary>
    /// Terminates a specific IPv4 TCP connection matching the local and remote endpoints.
    /// Returns true if the connection was located and successfully terminated.
    /// </summary>
    bool TerminateConnection(IPEndPoint local, IPEndPoint remote);
}
