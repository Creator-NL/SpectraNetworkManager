using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace SpectraNetworkManager.Platform.Windows;

/// <summary>
/// Monitors Windows DNS Client query events using ETW (Microsoft-Windows-DNS-Client provider).
/// Captures which process ID and application initiated each DNS query on the system.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EtwDnsClientMonitor : IDisposable
{
    public const string SessionName = "SpectraNetworkManager-DnsClient-ETW";
    public static readonly Guid DnsClientGuid = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    private TraceEventSession? _session;
    private Task? _processingTask;
    private readonly ConcurrentDictionary<string, (string Program, int Pid, DateTimeOffset LastSeen)> _recentCallers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ProcessResolver _processResolver = new();
    private bool _disposed;

    public bool IsRunning => _session != null && !_disposed;
    public bool IsElevated { get; }

    public EtwDnsClientMonitor()
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

            session.EnableProvider(DnsClientGuid, TraceEventLevel.Informational, 0x8000000000000000);

            session.Source.Dynamic.All += data =>
            {
                try
                {
                    if (data.ProcessID <= 4) return;
                    string? queryName = data.PayloadByName("QueryName") as string;
                    if (string.IsNullOrWhiteSpace(queryName)) return;

                    string cleanDomain = queryName.Trim().TrimEnd('.');
                    var proc = _processResolver.Resolve(data.ProcessID);
                    if (!string.IsNullOrEmpty(proc.Name))
                    {
                        _recentCallers[cleanDomain] = (proc.Name, data.ProcessID, DateTimeOffset.UtcNow);
                    }
                }
                catch { }
            };

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

    public bool TryGetCaller(string domain, out (string Program, int Pid) caller)
    {
        string cleanDomain = domain.Trim().TrimEnd('.');
        if (_recentCallers.TryGetValue(cleanDomain, out var entry))
        {
            if (DateTimeOffset.UtcNow - entry.LastSeen < TimeSpan.FromMinutes(10))
            {
                caller = (entry.Program, entry.Pid);
                return true;
            }
        }
        caller = default;
        return false;
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

        try
        {
            _session?.Stop(true);
            _session?.Dispose();
        }
        catch { }

        _recentCallers.Clear();
    }
}
