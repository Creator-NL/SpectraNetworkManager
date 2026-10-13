using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace NetSentinel.Platform.Windows;

public sealed record ProcessBandwidthSample(
    int Pid,
    long BytesReceivedPerSec,
    long BytesSentPerSec,
    long TotalBytesReceived,
    long TotalBytesSent);

/// <summary>
/// Monitors per-process network bandwidth (bytes sent/received) using ETW (Event Tracing for Windows).
/// Requires Administrator/LocalSystem privileges. Safely cleans up stale sessions on startup and disposal.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EtwBandwidthMonitor : IDisposable
{
    public const string SessionName = "NetSentinel-Network-ETW";

    private TraceEventSession? _session;
    private Task? _processingTask;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<int, PidCounters> _counters = new();
    private bool _disposed;

    public bool IsRunning => _session != null && !_disposed;
    public bool IsElevated { get; }

    public EtwBandwidthMonitor()
    {
        IsElevated = IsAdministrator();
    }

    public bool TryStart()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_session != null) return true;
        if (!IsElevated) return false;

        try
        {
            // Clean up any stale sessions left over from previous crashes
            try
            {
                var existing = TraceEventSession.GetActiveSession(SessionName);
                existing?.Stop(true);
            }
            catch { }

            var session = new TraceEventSession(SessionName, TraceEventSessionOptions.Create)
            {
                StopOnDispose = true
            };

            session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

            session.Source.Kernel.TcpIpSend += data => RecordSend(data.ProcessID, data.size);
            session.Source.Kernel.TcpIpRecv += data => RecordRecv(data.ProcessID, data.size);
            session.Source.Kernel.UdpIpSend += data => RecordSend(data.ProcessID, data.size);
            session.Source.Kernel.UdpIpRecv += data => RecordRecv(data.ProcessID, data.size);

            _session = session;
            _processingTask = Task.Run(() =>
            {
                try { session.Source.Process(); } catch { }
            });

            return true;
        }
        catch (Exception)
        {
            _session?.Dispose();
            _session = null;
            return false;
        }
    }

    private void RecordSend(int pid, int bytes)
    {
        if (pid <= 0 || bytes <= 0) return;
        var c = _counters.GetOrAdd(pid, _ => new PidCounters());
        Interlocked.Add(ref c.SentCurrentInterval, bytes);
        Interlocked.Add(ref c.TotalSent, bytes);
    }

    private void RecordRecv(int pid, int bytes)
    {
        if (pid <= 0 || bytes <= 0) return;
        var c = _counters.GetOrAdd(pid, _ => new PidCounters());
        Interlocked.Add(ref c.RecvCurrentInterval, bytes);
        Interlocked.Add(ref c.TotalRecv, bytes);
    }

    /// <summary>
    /// Captures a snapshot of bandwidth rates (per-second rates computed from interval delta).
    /// </summary>
    public IReadOnlyDictionary<int, ProcessBandwidthSample> HarvestInterval(double intervalSeconds)
    {
        var result = new Dictionary<int, ProcessBandwidthSample>(_counters.Count);
        if (intervalSeconds <= 0) intervalSeconds = 1.0;

        foreach (var kvp in _counters)
        {
            int pid = kvp.Key;
            var c = kvp.Value;

            long sent = Interlocked.Exchange(ref c.SentCurrentInterval, 0);
            long recv = Interlocked.Exchange(ref c.RecvCurrentInterval, 0);
            long totalSent = Interlocked.Read(ref c.TotalSent);
            long totalRecv = Interlocked.Read(ref c.TotalRecv);

            long sentRate = (long)(sent / intervalSeconds);
            long recvRate = (long)(recv / intervalSeconds);

            result[pid] = new ProcessBandwidthSample(pid, recvRate, sentRate, totalRecv, totalSent);
        }

        return result;
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();

        try
        {
            _session?.Stop(true);
            _session?.Dispose();
        }
        catch { }

        _counters.Clear();
        _cts.Dispose();
    }

    private sealed class PidCounters
    {
        public long SentCurrentInterval;
        public long RecvCurrentInterval;
        public long TotalSent;
        public long TotalRecv;
    }
}
