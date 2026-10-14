using System.Diagnostics;
using System.Security.Principal;
using System.Windows;
using NetSentinel.Core;
using NetSentinel.Core.Ipc;
using NetSentinel.Platform.Windows;

namespace NetSentinel.Ui;

public partial class App : System.Windows.Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 1. Global crash and unhandled exception logging
        SetupGlobalExceptionHandling();

        // 2. Command-line argument inspection: Safe Recovery Mode
        if (IsSafeRecoveryRequested(e.Args))
        {
            await ExecuteSafeRecoveryAsync();
            return;
        }

        // 3. First-Run Wizard check
        var settingsStore = new AppSettingsStore();
        if (!settingsStore.Settings.FirstRunCompleted)
        {
            var wizard = new FirstRunWizardWindow();
            bool? completed = wizard.ShowDialog();
            if (completed != true && !settingsStore.Settings.FirstRunCompleted)
            {
                Shutdown(0);
                return;
            }
        }

        // 4. Launch main application window
        var mainWindow = new MainWindow();
        MainWindow = mainWindow;
        mainWindow.Show();
    }

    private static bool IsSafeRecoveryRequested(string[] args)
    {
        foreach (var arg in args)
        {
            if (string.Equals(arg, "--safe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(arg, "-safe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(arg, "--recovery", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(arg, "-recovery", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(arg, "/safe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(arg, "/recovery", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static async Task ExecuteSafeRecoveryAsync()
    {
        RotatingFileLogger.LogInfo("Safe Recovery Mode triggered via command line.");

        bool restoredViaIpc = false;
        try
        {
            using var ipcClient = new IpcClient();
            await ipcClient.ConnectAsync(TimeSpan.FromSeconds(2));
            if (ipcClient.IsConnected)
            {
                var res = await ipcClient.SendRequestAsync(IpcConstants.Actions.Panic, timeout: TimeSpan.FromSeconds(5));
                if (res.Success)
                {
                    restoredViaIpc = true;
                    RotatingFileLogger.LogInfo("Safe Recovery executed via NetSentinel Engine service.");
                }
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Engine service IPC unreachable for recovery: {ex.Message}");
        }

        int removedRules = 0;
        if (!restoredViaIpc)
        {
            if (!IsAdministrator())
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = Environment.ProcessPath ?? "NetSentinel.exe",
                        Arguments = "--safe",
                        UseShellExecute = true,
                        Verb = "runas"
                    };
                    Process.Start(psi);
                    Current.Shutdown(0);
                    return;
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        "Administrator permissions are required to restore Windows Firewall rules and system DNS settings in Safe Recovery Mode.\n\n" + ex.Message,
                        "NetSentinel Safe Recovery - Elevation Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    Current.Shutdown(1);
                    return;
                }
            }

            // Revert strict mode defaults
            try
            {
                var strictStore = new StrictModeStore(StrictModeStore.DefaultPath);
                var enforcer = new WindowsFirewallEnforcer();
                var prev = strictStore.State.Previous ?? ProfileDefaults.StandardWindows;
                enforcer.SetDefaultOutbound(prev);
                enforcer.RemoveAllAllowRules();
                strictStore.Save(StrictModeState.Off);
                RotatingFileLogger.LogInfo("Safe Recovery: Strict mode defaults reverted to Standard Windows.");
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogError("Safe Recovery: Failed to revert strict mode defaults", ex);
            }

            // Restore system DNS
            try
            {
                var dnsSwitch = new SystemDnsSwitchManager(null, null, null);
                await dnsSwitch.RestoreAllAsync();
                RotatingFileLogger.LogInfo("Safe Recovery: System DNS restored on all adapters.");
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogError("Safe Recovery: Failed to restore system DNS", ex);
            }

            // Remove all NetSentinel rules
            try
            {
                var enforcer = new WindowsFirewallEnforcer();
                removedRules = enforcer.RemoveAll();
                RotatingFileLogger.LogInfo($"Safe Recovery: Removed {removedRules} NetSentinel firewall rules.");
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogError("Safe Recovery: Failed to remove firewall rules", ex);
            }

            // Clear block decisions from rule store
            try
            {
                var ruleStore = new RuleStore(RuleStore.DefaultPath);
                ruleStore.RemoveWhere(r => r.Action == RuleAction.Block);
                RotatingFileLogger.LogInfo("Safe Recovery: Cleared block decisions.");
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogError("Safe Recovery: Failed to clear block decisions", ex);
            }
        }

        MessageBox.Show(
            "NetSentinel Safe Recovery Mode Completed:\n\n" +
            (restoredViaIpc
                ? "• All defaults and network configurations restored via NetSentinel Engine service.\n"
                : $"• Removed {removedRules} NetSentinel firewall rules.\n" +
                  "• Firewall outbound default restored to Allow.\n" +
                  "• System DNS restored to original network adapter configuration.\n" +
                  "• Temporary block decisions cleared.\n\n") +
            "Your network connectivity is restored.",
            "NetSentinel Safe Recovery", MessageBoxButton.OK, MessageBoxImage.Information);

        Current.Shutdown(0);
    }

    private void SetupGlobalExceptionHandling()
    {
        DispatcherUnhandledException += (s, e) =>
        {
            RotatingFileLogger.LogError("CRASH (DispatcherUnhandledException)", e.Exception);
            MessageBox.Show(
                $"An unexpected error occurred in NetSentinel:\n\n{e.Exception.Message}\n\n" +
                $"Details have been logged to:\n{EngineStoragePaths.LogFilePath}\n\n" +
                "If you are experiencing network connectivity issues, start NetSentinel in Safe Recovery Mode (NetSentinel.exe --safe).",
                "NetSentinel Error", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        };

        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            if (e.ExceptionObject is Exception ex)
            {
                RotatingFileLogger.LogError("CRASH (AppDomain UnhandledException)", ex);
            }
            else
            {
                RotatingFileLogger.LogError($"CRASH (AppDomain UnhandledException): {e.ExceptionObject}");
            }
        };

        TaskScheduler.UnobservedTaskException += (s, e) =>
        {
            RotatingFileLogger.LogError("CRASH (UnobservedTaskException)", e.Exception);
            e.SetObserved();
        };
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
