using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

/// <summary>Maps a PID to a program name, full image path, parent PID/name, command line, start time, and hosted Windows services.</summary>
[SupportedOSPlatform("windows")]
public sealed class ProcessResolver : IProcessResolver
{
    private readonly ConcurrentDictionary<int, ProcessInfo> _cache = new();

    public ProcessInfo Resolve(int pid)
    {
        if (pid == 0) return new ProcessInfo(0, "(none / closing)", null);
        if (pid == 4) return new ProcessInfo(4, "System", null);

        if (_cache.TryGetValue(pid, out var cached))
        {
            // Guard against Windows PID reuse: verify start time if we have one.
            var currentStart = TryGetProcessStartTimeUtc(pid);
            if (currentStart == cached.StartTimeUtc)
            {
                // If svchost or another host process started hosting a service after initial lookup, refresh service names if empty.
                if (string.IsNullOrEmpty(cached.ServiceNames))
                {
                    var svc = WindowsServiceManager.GetServiceSummaryForPid(pid);
                    if (!string.IsNullOrEmpty(svc))
                    {
                        cached = cached with { ServiceNames = svc };
                        _cache[pid] = cached;
                    }
                }
                return cached;
            }
        }

        var info = Lookup(pid);
        _cache[pid] = info;
        return info;
    }

    public void Remove(int pid) => _cache.TryRemove(pid, out _);

    // PIDs are reused by Windows, so drop entries for processes that are gone.
    public void Prune(IReadOnlySet<int> alivePids)
    {
        foreach (var pid in _cache.Keys)
        {
            if (!alivePids.Contains(pid))
                _cache.TryRemove(pid, out _);
        }
    }

    private ProcessInfo Lookup(int pid)
    {
        if (pid == 0) return new ProcessInfo(0, "(none / closing)", null);
        if (pid == 4) return new ProcessInfo(4, "System", null);

        string? path = null;
        DateTimeOffset? startTimeUtc = null;
        int? parentPid = null;
        string? commandLine = null;

        IntPtr handle = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                path = QueryImagePathFromHandle(handle);
                startTimeUtc = QueryStartTimeFromHandle(handle);
                parentPid = QueryParentPidFromHandle(handle);
                commandLine = QueryCommandLineFromHandle(handle);
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }
        }

        string? parentName = null;
        if (parentPid is > 0 && parentPid.Value != pid)
        {
            parentName = QueryQuickProcessName(parentPid.Value);
        }

        string? serviceNames = WindowsServiceManager.GetServiceSummaryForPid(pid);

        if (path is not null)
        {
            return new ProcessInfo(
                pid,
                System.IO.Path.GetFileName(path),
                path,
                parentPid,
                parentName,
                commandLine,
                startTimeUtc,
                serviceNames);
        }

        // Protected processes refuse the path query; the name is often still readable.
        try
        {
            using var p = Process.GetProcessById(pid);
            return new ProcessInfo(
                pid,
                p.ProcessName,
                null,
                parentPid,
                parentName,
                commandLine,
                startTimeUtc,
                serviceNames);
        }
        catch (Exception)
        {
            return new ProcessInfo(pid, $"(pid {pid})", null, parentPid, parentName, commandLine, startTimeUtc, serviceNames);
        }
    }

    private static DateTimeOffset? TryGetProcessStartTimeUtc(int pid)
    {
        IntPtr handle = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            return QueryStartTimeFromHandle(handle);
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    private static string? QueryQuickProcessName(int pid)
    {
        if (pid == 0) return "System Idle";
        if (pid == 4) return "System";

        IntPtr handle = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var p = QueryImagePathFromHandle(handle);
                if (!string.IsNullOrEmpty(p))
                    return System.IO.Path.GetFileName(p);
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }
        }

        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch
        {
            return null;
        }
    }

    private static string? QueryImagePathFromHandle(IntPtr handle)
    {
        var sb = new StringBuilder(1024);
        int size = sb.Capacity;
        return NativeMethods.QueryFullProcessImageNameW(handle, 0, sb, ref size) ? sb.ToString(0, size) : null;
    }

    private static DateTimeOffset? QueryStartTimeFromHandle(IntPtr handle)
    {
        if (NativeMethods.GetProcessTimes(handle, out long creationTime, out _, out _, out _) && creationTime > 0)
        {
            try
            {
                return DateTimeOffset.FromFileTime(creationTime).ToUniversalTime();
            }
            catch
            {
                return null;
            }
        }
        return null;
    }

    private static int? QueryParentPidFromHandle(IntPtr handle)
    {
        int size = Marshal.SizeOf<NativeMethods.ProcessBasicInformation>();
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            int status = NativeMethods.NtQueryInformationProcess(
                handle,
                NativeMethods.ProcessBasicInformationClass,
                buffer,
                size,
                out _);
            if (status == 0)
            {
                var pbi = Marshal.PtrToStructure<NativeMethods.ProcessBasicInformation>(buffer);
                int ppid = (int)pbi.InheritedFromUniqueProcessId.ToInt64();
                return ppid > 0 ? ppid : null;
            }
        }
        catch
        {
            // Ignore
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return null;
    }

    private static string? QueryCommandLineFromHandle(IntPtr handle)
    {
        int returnLength = 0;
        NativeMethods.NtQueryInformationProcess(
            handle,
            NativeMethods.ProcessCommandLineInformationClass,
            IntPtr.Zero,
            0,
            out returnLength);

        if (returnLength <= 0 || returnLength > 65536) return null;

        IntPtr buffer = Marshal.AllocHGlobal(returnLength);
        try
        {
            int status = NativeMethods.NtQueryInformationProcess(
                handle,
                NativeMethods.ProcessCommandLineInformationClass,
                buffer,
                returnLength,
                out _);

            if (status == 0)
            {
                var unicodeStr = Marshal.PtrToStructure<NativeMethods.UnicodeString>(buffer);
                if (unicodeStr.Length > 0 && unicodeStr.Buffer != IntPtr.Zero)
                {
                    int charCount = unicodeStr.Length / 2;
                    string raw = Marshal.PtrToStringUni(unicodeStr.Buffer, charCount) ?? "";
                    raw = raw.Trim();
                    if (raw.Length > 512)
                        raw = raw[..512] + "…";
                    return string.IsNullOrWhiteSpace(raw) ? null : raw;
                }
            }
        }
        catch
        {
            // Ignore
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return null;
    }
}
