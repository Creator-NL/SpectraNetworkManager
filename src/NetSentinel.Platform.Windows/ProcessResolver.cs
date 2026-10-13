using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using NetSentinel.Core;

namespace NetSentinel.Platform.Windows;

/// <summary>Maps a PID to a program name and full image path, with a small cache.</summary>
[SupportedOSPlatform("windows")]
public sealed class ProcessResolver : IProcessResolver
{
    private readonly Dictionary<int, ProcessInfo> _cache = new();

    public ProcessInfo Resolve(int pid)
    {
        if (_cache.TryGetValue(pid, out var cached)) return cached;
        var info = Lookup(pid);
        _cache[pid] = info;
        return info;
    }

    // PIDs are reused by Windows, so drop entries for processes that are gone.
    public void Prune(IReadOnlySet<int> alivePids)
    {
        foreach (var pid in _cache.Keys.Where(p => !alivePids.Contains(p)).ToList())
            _cache.Remove(pid);
    }

    private static ProcessInfo Lookup(int pid)
    {
        if (pid == 0) return new ProcessInfo(0, "(none / closing)", null);
        if (pid == 4) return new ProcessInfo(4, "System", null);

        string? path = QueryImagePath(pid);
        if (path is not null)
            return new ProcessInfo(pid, System.IO.Path.GetFileName(path), path);

        // Protected processes refuse the path query; the name is often still readable.
        try
        {
            using var p = Process.GetProcessById(pid);
            return new ProcessInfo(pid, p.ProcessName, null);
        }
        catch (Exception)
        {
            return new ProcessInfo(pid, $"(pid {pid})", null);
        }
    }

    private static string? QueryImagePath(int pid)
    {
        IntPtr handle = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return NativeMethods.QueryFullProcessImageNameW(handle, 0, sb, ref size) ? sb.ToString(0, size) : null;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }
}
