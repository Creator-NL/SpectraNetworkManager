using System.Net;

namespace SpectraNetworkManager.Core;

public enum Protocol { Tcp, Udp }

public enum ConnectionState
{
    /// <summary>UDP has no connection state.</summary>
    None = 0,
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12,
}

/// <summary>One TCP connection / listener or UDP endpoint at a point in time.</summary>
public sealed record ConnectionInfo(
    Protocol Protocol,
    IPEndPoint Local,
    IPEndPoint? Remote,
    ConnectionState State,
    int ProcessId);

/// <summary>The program that owns a connection.</summary>
public sealed record ProcessInfo(int Pid, string Name, string? Path);

/// <summary>A connection together with its resolved owner, ready for display.</summary>
public sealed record ConnectionView(ConnectionInfo Connection, ProcessInfo Process);
