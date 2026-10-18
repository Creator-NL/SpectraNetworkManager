using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

[SupportedOSPlatform("windows")]
public static class ElevationHelper
{
    private const string AppCompatLayersKey = @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";

    public static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Elevation check error: {ex.Message}");
            return false;
        }
    }

    public static bool StartProcessElevated(string exePath, string? arguments = null)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arguments ?? string.Empty,
                UseShellExecute = true,
                Verb = "runas"
            };
            Process.Start(psi);
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED (user clicked No on UAC)
        {
            RotatingFileLogger.LogInfo("Elevation prompt was cancelled by user.");
            return false;
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogError("Failed to start process elevated", ex);
            return false;
        }
    }

    public static bool StartProcessUnelevated(string exePath, string? arguments = null)
    {
        // 1. Try launching via token duplication from interactive explorer.exe shell
        try
        {
            if (StartViaExplorerToken(exePath, arguments))
            {
                RotatingFileLogger.LogInfo("Successfully launched unelevated process via Explorer desktop token.");
                return true;
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Explorer token launch attempt failed: {ex.Message}");
        }

        // 2. Fallback: Launch standard ProcessStartInfo without 'runas'
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arguments ?? string.Empty,
                UseShellExecute = true
            };
            Process.Start(psi);
            RotatingFileLogger.LogInfo("Launched process via standard Process.Start fallback.");
            return true;
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogError("Failed to launch process unelevated", ex);
            return false;
        }
    }

    public static void SetAlwaysRunAsAdminRegistry(string exePath, bool enable)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(AppCompatLayersKey, writable: true);
            if (key != null)
            {
                if (enable)
                {
                    key.SetValue(exePath, "~ RUNASADMIN", RegistryValueKind.String);
                    RotatingFileLogger.LogInfo($"Enabled RUNASADMIN AppCompatFlags for {exePath}");
                }
                else
                {
                    key.DeleteValue(exePath, throwOnMissingValue: false);
                    RotatingFileLogger.LogInfo($"Cleared RUNASADMIN AppCompatFlags for {exePath}");
                }
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Failed to update AppCompatFlags registry for {exePath}: {ex.Message}");
        }
    }

    public static bool IsAlwaysRunAsAdminRegistry(string exePath)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(AppCompatLayersKey, writable: false);
            if (key != null)
            {
                var val = key.GetValue(exePath) as string;
                return !string.IsNullOrEmpty(val) && val.Contains("RUNASADMIN", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Failed to read AppCompatFlags registry for {exePath}: {ex.Message}");
        }
        return false;
    }

    private static bool StartViaExplorerToken(string exePath, string? arguments)
    {
        uint explorerPid = 0;
        IntPtr shellHwnd = GetShellWindow();
        if (shellHwnd != IntPtr.Zero)
        {
            GetWindowThreadProcessId(shellHwnd, out explorerPid);
        }

        if (explorerPid == 0)
        {
            var procs = Process.GetProcessesByName("explorer");
            if (procs.Length > 0)
            {
                explorerPid = (uint)procs[0].Id;
            }
        }

        if (explorerPid == 0) return false;

        IntPtr hProcess = OpenProcess(ProcessQueryLimitedInformation, false, (int)explorerPid);
        if (hProcess == IntPtr.Zero) return false;

        try
        {
            if (!OpenProcessToken(hProcess, TokenDuplicate | TokenQuery, out IntPtr hToken))
                return false;

            try
            {
                if (!DuplicateTokenEx(hToken, TokenAllAccess, IntPtr.Zero, 2 /* SecurityImpersonation */, 1 /* TokenPrimary */, out IntPtr hPrimaryToken))
                    return false;

                try
                {
                    var si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    string cmd = string.IsNullOrEmpty(arguments) ? $"\"{exePath}\"" : $"\"{exePath}\" {arguments}";
                    string? dir = Path.GetDirectoryName(exePath);

                    if (CreateProcessWithTokenW(hPrimaryToken, 0, exePath, cmd, 0, IntPtr.Zero, dir, ref si, out var pi))
                    {
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        return true;
                    }
                }
                finally
                {
                    CloseHandle(hPrimaryToken);
                }
            }
            finally
            {
                CloseHandle(hToken);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }

        return false;
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAllAccess = 0x000F01FF;

    [DllImport("user32.dll")]
    private static extern IntPtr GetShellWindow();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int impersonationLevel,
        int tokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        uint dwLogonFlags,
        string? lpApplicationName,
        string? lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
}
