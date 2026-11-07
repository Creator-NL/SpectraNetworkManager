using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Windows;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Platform.Windows;

namespace SpectraNetworkManager.Ui;

/// <summary>
/// Enforces single-instance execution for SpectraNetworkManager.
/// If an instance is already running, signals it to restore and bring its window to the front,
/// preventing duplicate processes, port 53 socket conflicts, and driver handle collisions.
/// </summary>
internal static class SingleInstanceManager
{
    private static Mutex? _mutex;
    private static bool _mutexOwned;
    private static CancellationTokenSource? _cts;
    private static Task? _listenerTask;

    private static string PipeName => WindowsPipeSecurityHelper.SingleInstancePipeName;

    private static string MutexName =>
        $@"Local\SpectraNetworkManager_{Environment.UserName}_SingleInstance_Mutex";

    /// <summary>
    /// Event fired when a native messaging host or external component notifies that Browser Guard rules changed.
    /// </summary>
    public static event Action? BrowserGuardChanged;

    /// <summary>
    /// Initializes single-instance enforcement.
    /// Returns true if this process is the primary (first) instance;
    /// returns false if an instance is already running (and signals that instance to activate).
    /// </summary>
    public static bool InitializeAsFirstInstance(Action onActivateRequested, string[]? args = null)
    {
        // 1. Check for intentional restart handoff from an exiting instance
        int restartPid = 0;
        if (args != null)
        {
            foreach (var arg in args)
            {
                if (arg.StartsWith("--restart-from=", StringComparison.OrdinalIgnoreCase))
                {
                    _ = int.TryParse(arg["--restart-from=".Length..], out restartPid);
                    break;
                }
            }
        }

        if (restartPid > 0)
        {
            try
            {
                var parentProc = Process.GetProcessById(restartPid);
                if (!parentProc.HasExited)
                {
                    RotatingFileLogger.LogInfo($"SingleInstanceManager: Waiting for previous instance PID {restartPid} to exit...");
                    parentProc.WaitForExit(5000); // Wait up to 5 seconds
                }
            }
            catch (ArgumentException)
            {
                // Process already exited, perfectly fine
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogWarn($"SingleInstanceManager: Error waiting for PID {restartPid}: {ex.Message}");
            }
        }

        bool isFirstInstance = false;
        try
        {
            _mutex = new Mutex(true, MutexName, out bool createdNew);
            if (createdNew)
            {
                isFirstInstance = true;
                _mutexOwned = true;
            }
            else
            {
                try
                {
                    // Check if the existing mutex is actively held or was abandoned by a crashed/exiting process
                    int waitTimeout = restartPid > 0 ? 3000 : 250;
                    if (_mutex.WaitOne(waitTimeout, false))
                    {
                        isFirstInstance = true;
                        _mutexOwned = true;
                    }
                }
                catch (AbandonedMutexException)
                {
                    // Previous instance terminated without cleanly releasing mutex.
                    // We now hold ownership and become the primary instance.
                    isFirstInstance = true;
                    _mutexOwned = true;
                }
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"SingleInstanceManager: Mutex check encountered an exception ({ex.Message}). Falling back to process inspection.");
            var current = Process.GetCurrentProcess();
            var running = Process.GetProcessesByName(current.ProcessName)
                .Any(p => p.Id != current.Id && p.SessionId == current.SessionId);
            isFirstInstance = !running;
        }

        if (!isFirstInstance)
        {
            RotatingFileLogger.LogInfo("SpectraNetworkManager is already running. Signaling existing instance to activate...");
            bool signaled = NotifyExistingInstanceToActivate();
            if (!signaled)
            {
                MessageBox.Show(
                    "SpectraNetworkManager is already running in your system tray or taskbar.\n\nPlease check the notification area at the bottom-right of your screen.",
                    "SpectraNetworkManager - Already Running",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            return false;
        }

        // We are the first instance: start listening for subsequent launches
        _cts = new CancellationTokenSource();
        _listenerTask = Task.Run(() => StartPipeListenerAsync(onActivateRequested, _cts.Token));
        return true;
    }

    /// <summary>
    /// Signals the primary running instance via Named Pipe and transfers foreground activation permissions.
    /// </summary>
    public static bool NotifyExistingInstanceToActivate()
    {
        try
        {
            // Allow the primary instance to take foreground focus without Windows blocking it
            NativeMethods.AllowSetForegroundWindow(NativeMethods.ASFW_ANY);

            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
            client.Connect(1500); // Wait up to 1.5 seconds

            using var writer = new StreamWriter(client, Encoding.UTF8) { AutoFlush = true };
            writer.WriteLine("ACTIVATE");
            return true;
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"SingleInstanceManager: Could not connect to running instance pipe: {ex.Message}");

            // Fallback: Find the existing process window directly and restore it
            try
            {
                var current = Process.GetCurrentProcess();
                var other = Process.GetProcessesByName(current.ProcessName)
                    .FirstOrDefault(p => p.Id != current.Id && p.SessionId == current.SessionId);

                if (other != null)
                {
                    NativeMethods.AllowSetForegroundWindow(other.Id);
                    if (other.MainWindowHandle != IntPtr.Zero)
                    {
                        NativeMethods.ShowWindow(other.MainWindowHandle, NativeMethods.SW_RESTORE);
                        NativeMethods.SetForegroundWindow(other.MainWindowHandle);
                        return true;
                    }
                }
            }
            catch { /* best effort */ }

            return false;
        }
    }

    private static async Task StartPipeListenerAsync(Action onActivateRequested, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var server = WindowsPipeSecurityHelper.CreateSecuredServerStream(PipeName);
                await server.WaitForConnectionAsync(ct);

                using var reader = new StreamReader(server, Encoding.UTF8);
                string? command = await reader.ReadLineAsync(ct);

                if (string.Equals(command, "ACTIVATE", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        onActivateRequested();
                    }
                    catch (Exception ex)
                    {
                        RotatingFileLogger.LogError("Error in single instance activation handler", ex);
                    }
                }
                else if (string.Equals(command, "BROWSER_GUARD_CHANGED", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        BrowserGuardChanged?.Invoke();
                    }
                    catch (Exception ex)
                    {
                        RotatingFileLogger.LogError("Error in single instance BrowserGuardChanged handler", ex);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) break;
                RotatingFileLogger.LogWarn($"SingleInstanceManager listener loop error: {ex.Message}");
                await Task.Delay(500, ct);
            }
        }
    }

    /// <summary>
    /// Releases mutex ownership and terminates pipe listener immediately ahead of an intentional elevation/restart handoff.
    /// This prevents the newly spawned instance from falsely detecting an already-running instance.
    /// </summary>
    public static void PrepareForRestart()
    {
        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;

            if (_mutexOwned && _mutex != null)
            {
                _mutex.ReleaseMutex();
                _mutexOwned = false;
            }
            _mutex?.Dispose();
            _mutex = null;

            RotatingFileLogger.LogInfo("SingleInstanceManager: Mutex and pipe listener cleanly released for restart handoff.");
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"SingleInstanceManager: Exception in PrepareForRestart ({ex.Message}).");
        }
    }

    /// <summary>
    /// Cleans up the single instance mutex and named pipe listener upon application shutdown.
    /// </summary>
    public static void Dispose()
    {
        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;

            if (_mutexOwned && _mutex != null)
            {
                _mutex.ReleaseMutex();
                _mutexOwned = false;
            }
            _mutex?.Dispose();
            _mutex = null;
        }
        catch { /* best effort on process exit */ }
    }
}
