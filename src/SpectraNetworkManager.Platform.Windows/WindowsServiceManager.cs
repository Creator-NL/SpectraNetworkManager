using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SpectraNetworkManager.Platform.Windows;

public sealed record DiscoveredService(string ServiceName, string DisplayName, int ProcessId, uint State)
{
    public string StateDescription => State switch
    {
        1 => "Stopped",
        2 => "Start Pending",
        3 => "Stop Pending",
        4 => "Running",
        5 => "Continue Pending",
        6 => "Pause Pending",
        7 => "Paused",
        _ => $"State ({State})"
    };
}

/// <summary>
/// Discovers and manages Windows Services associated with active connections and processes.
/// Uses native Win32 EnumServicesStatusEx for high-performance zero-overhead service discovery.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsServiceManager
{
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    private const int SC_ENUM_PROCESS_INFO = 0;
    private const uint SERVICE_WIN32 = 0x00000030;
    private const uint SERVICE_STATE_ALL = 0x00000003;
    private const uint SERVICE_STOP = 0x0020;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint SERVICE_CONTROL_STOP = 0x00000001;
    private const uint SERVICE_STOPPED = 0x00000001;
    private const int ERROR_MORE_DATA = 234;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool EnumServicesStatusEx(
        IntPtr hSCManager,
        int infoLevel,
        uint dwServiceType,
        uint dwServiceState,
        IntPtr lpServices,
        uint cbBufSize,
        out uint pcbBytesNeeded,
        out uint lpServicesReturned,
        ref uint lpResumeHandle,
        string? pszGroupName);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(IntPtr hService, ref SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ENUM_SERVICE_STATUS_PROCESS
    {
        public IntPtr lpServiceName;
        public IntPtr lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }

    /// <summary>
    /// Enumerates all Windows Services currently assigned to the given process ID.
    /// </summary>
    public static List<DiscoveredService> GetServicesForPid(int pid)
    {
        var result = new List<DiscoveredService>();
        if (pid <= 4) return result;

        IntPtr hSC = OpenSCManager(null, null, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (hSC == IntPtr.Zero) return result;

        try
        {
            uint bytesNeeded = 0;
            uint servicesReturned = 0;
            uint resumeHandle = 0;

            EnumServicesStatusEx(hSC, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                IntPtr.Zero, 0, out bytesNeeded, out servicesReturned, ref resumeHandle, null);

            if (bytesNeeded == 0) return result;

            IntPtr buffer = Marshal.AllocHGlobal((int)bytesNeeded);
            try
            {
                if (EnumServicesStatusEx(hSC, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                    buffer, bytesNeeded, out bytesNeeded, out servicesReturned, ref resumeHandle, null))
                {
                    int structSize = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESS>();
                    for (int i = 0; i < servicesReturned; i++)
                    {
                        IntPtr currentPtr = IntPtr.Add(buffer, i * structSize);
                        var item = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESS>(currentPtr);
                        if (item.ServiceStatusProcess.dwProcessId == (uint)pid)
                        {
                            string sName = Marshal.PtrToStringUni(item.lpServiceName) ?? "";
                            string dName = Marshal.PtrToStringUni(item.lpDisplayName) ?? sName;
                            result.Add(new DiscoveredService(sName, dName, pid, item.ServiceStatusProcess.dwCurrentState));
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            // Non-fatal fallback
        }
        finally
        {
            CloseServiceHandle(hSC);
        }

        return result;
    }

    /// <summary>
    /// Discovers services associated with a process ID or executable name.
    /// </summary>
    public static List<DiscoveredService> GetServicesForProcess(int pid, string programName)
    {
        var services = GetServicesForPid(pid);
        if (services.Count > 0) return services;

        // If PID-based search yielded nothing (e.g. process just restarted or access restricted),
        // check all services where ServiceName or DisplayName matches the program name.
        if (string.IsNullOrWhiteSpace(programName)) return services;
        string cleanName = Path.GetFileNameWithoutExtension(programName);

        IntPtr hSC = OpenSCManager(null, null, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (hSC == IntPtr.Zero) return services;

        try
        {
            uint bytesNeeded = 0;
            uint servicesReturned = 0;
            uint resumeHandle = 0;

            EnumServicesStatusEx(hSC, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                IntPtr.Zero, 0, out bytesNeeded, out servicesReturned, ref resumeHandle, null);

            if (bytesNeeded == 0) return services;

            IntPtr buffer = Marshal.AllocHGlobal((int)bytesNeeded);
            try
            {
                if (EnumServicesStatusEx(hSC, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                    buffer, bytesNeeded, out bytesNeeded, out servicesReturned, ref resumeHandle, null))
                {
                    int structSize = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESS>();
                    for (int i = 0; i < servicesReturned; i++)
                    {
                        IntPtr currentPtr = IntPtr.Add(buffer, i * structSize);
                        var item = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESS>(currentPtr);
                        string sName = Marshal.PtrToStringUni(item.lpServiceName) ?? "";
                        string dName = Marshal.PtrToStringUni(item.lpDisplayName) ?? sName;

                        if (sName.Equals(cleanName, StringComparison.OrdinalIgnoreCase) ||
                            dName.Equals(cleanName, StringComparison.OrdinalIgnoreCase))
                        {
                            services.Add(new DiscoveredService(sName, dName, (int)item.ServiceStatusProcess.dwProcessId, item.ServiceStatusProcess.dwCurrentState));
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch { }
        finally
        {
            CloseServiceHandle(hSC);
        }

        return services;
    }

    /// <summary>
    /// Stops the specified Windows Service. Prompts UAC elevation if not already running as Administrator.
    /// </summary>
    public static async Task<(bool Success, string Message)> StopServiceAsync(string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
            return (false, "Invalid service name.");

        IntPtr hSC = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (hSC != IntPtr.Zero)
        {
            IntPtr hService = OpenService(hSC, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (hService != IntPtr.Zero)
            {
                try
                {
                    var status = new SERVICE_STATUS();
                    if (ControlService(hService, SERVICE_CONTROL_STOP, ref status))
                    {
                        // Wait up to 5 seconds for service to reach stopped state
                        var sw = Stopwatch.StartNew();
                        while (sw.ElapsedMilliseconds < 5000)
                        {
                            await Task.Delay(250);
                            if (QueryServiceStatus(hService, ref status) && status.dwCurrentState == SERVICE_STOPPED)
                            {
                                return (true, $"Service '{serviceName}' was stopped successfully.");
                            }
                        }
                        return (true, $"Stop command delivered to '{serviceName}'.");
                    }
                }
                finally
                {
                    CloseServiceHandle(hService);
                    CloseServiceHandle(hSC);
                }
            }
            else
            {
                int error = Marshal.GetLastWin32Error();
                CloseServiceHandle(hSC);
                // Error 5 is ERROR_ACCESS_DENIED (requires Administrator)
                if (error == 5)
                {
                    return await RunElevatedScStopAsync(serviceName);
                }
            }
        }

        return await RunElevatedScStopAsync(serviceName);
    }

    private static async Task<(bool Success, string Message)> RunElevatedScStopAsync(string serviceName)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c sc.exe stop \"{serviceName}\"",
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden
            };

            var proc = Process.Start(psi);
            if (proc != null)
            {
                await proc.WaitForExitAsync();
                return proc.ExitCode == 0
                    ? (true, $"Service '{serviceName}' was stopped successfully with Administrator privileges.")
                    : (false, $"sc.exe stop exited with code {proc.ExitCode}.");
            }
            return (false, "Failed to start elevated sc.exe process.");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED (user canceled UAC)
        {
            return (false, "Administrator elevation prompt was canceled.");
        }
        catch (Exception ex)
        {
            return (false, $"Failed to stop service: {ex.Message}");
        }
    }
}
