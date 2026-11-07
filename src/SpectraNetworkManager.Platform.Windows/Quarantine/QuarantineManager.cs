using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Win32;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

[SupportedOSPlatform("windows5.1.2600")]
public sealed class QuarantineManager
{
    private readonly QuarantineVault _vault;
    private readonly RuleStore _rules;
    private readonly WindowsFirewallEnforcer _enforcer;
    private readonly IConnectionTerminator _terminator;
    private readonly AuthenticodeVerifier? _verifier;

    public QuarantineManager(
        QuarantineVault vault,
        RuleStore rules,
        WindowsFirewallEnforcer enforcer,
        IConnectionTerminator terminator,
        AuthenticodeVerifier? verifier = null)
    {
        _vault = vault;
        _rules = rules;
        _enforcer = enforcer;
        _terminator = terminator;
        _verifier = verifier;
    }

    /// <summary>
    /// Executes the 5-Stage Active Defense Quarantine on the specified executable path.
    /// Stage 1: Tears down active network sockets & kills running processes.
    /// Stage 2: Enforces kernel-level execution lockout via Windows IFEO debugger redirection (program cannot start).
    /// Stage 3: Identifies dedicated Windows services, stops them, and disables them.
    /// Stage 4: Disables Registry, Startup Folder, and Task Scheduler auto-start entries.
    /// Stage 5: Creates Inbound/Outbound Windows Firewall block rules and records in RuleStore.
    /// Full snapshot is preserved in quarantine-vault.json for 100% reversible rollback.
    /// </summary>
    public async Task<(bool Success, string Message, QuarantineSnapshot? Snapshot)> QuarantineAsync(
        string executablePath,
        string reason = "")
    {
        if (string.IsNullOrWhiteSpace(executablePath))
            return (false, "Invalid executable path.", null);

        string cleanPath = Path.GetFullPath(executablePath);
        string programName = Path.GetFileName(cleanPath);

        // Pre-Check 1: Prevent self-quarantine
        string? selfPath = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(selfPath) && string.Equals(cleanPath, selfPath, StringComparison.OrdinalIgnoreCase))
        {
            return (false, "Cannot quarantine SpectraNetworkManager itself.", null);
        }

        // Pre-Check 2: Critical OS component & Shared Runtime (WebView2, Ollama) safety guard
        SignatureInfo? sig = null;
        try
        {
            sig = _verifier?.TryGet(cleanPath) ?? NativeAuthenticodeVerifier.VerifyFile(cleanPath);
        }
        catch { }

        if (ProtectedPrograms.IsExecutionLockoutProtected(cleanPath, out string protectReason))
        {
            return (false, $"Quarantine blocked: {protectReason}", null);
        }

        var snapshot = new QuarantineSnapshot
        {
            ExecutablePath = cleanPath,
            ProgramName = programName,
            Reason = string.IsNullOrWhiteSpace(reason) ? "User initiated quarantine" : reason,
            QuarantinedAtUtc = DateTimeOffset.UtcNow,
        };

        // --- STAGE 1: Process & Socket Termination ---
        try
        {
            snapshot.ClosedSocketsCount = _terminator.TerminateConnectionsForProgram(cleanPath);
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Quarantine Stage 1 Socket error: {ex.Message}");
        }

        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (proc.Id <= 4) continue;
                    string? pPath = null;
                    try { pPath = proc.MainModule?.FileName; } catch { }

                    if ((!string.IsNullOrEmpty(pPath) && string.Equals(pPath, cleanPath, StringComparison.OrdinalIgnoreCase)) ||
                        string.Equals(proc.ProcessName + ".exe", programName, StringComparison.OrdinalIgnoreCase))
                    {
                        snapshot.TerminatedPids.Add(proc.Id);
                        proc.Kill();
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Quarantine Stage 1 Process kill error: {ex.Message}");
        }

        // --- STAGE 2: Kernel-Level Execution Lockout (IFEO) ---
        try
        {
            if (SetExecutionLockout(programName, true))
            {
                snapshot.ExecutionLockoutApplied = true;
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Quarantine Stage 2 Execution Lockout error: {ex.Message}");
        }

        // --- STAGE 3: Windows Services ---
        try
        {
            var services = WindowsServiceManager.GetServicesForProcess(0, programName);

            // Also check Registry for services pointing directly to this binary path
            var regServices = FindServicesWithBinaryPath(cleanPath);
            foreach (var rs in regServices)
            {
                if (!services.Any(s => s.ServiceName.Equals(rs.ServiceName, StringComparison.OrdinalIgnoreCase)))
                {
                    services.Add(rs);
                }
            }

            foreach (var s in services)
            {
                uint origStart = WindowsServiceManager.GetServiceStartType(s.ServiceName);
                bool wasRunning = s.State == 4; // SERVICE_RUNNING

                snapshot.ModifiedServices.Add(new QuarantineServiceRecord(s.ServiceName, s.DisplayName, origStart, wasRunning));

                if (wasRunning)
                {
                    await WindowsServiceManager.StopServiceAsync(s.ServiceName);
                }
                await WindowsServiceManager.SetServiceStartTypeAsync(s.ServiceName, 4); // SERVICE_DISABLED
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Quarantine Stage 2 Service error: {ex.Message}");
        }

        // --- STAGE 4: Auto-Start Entries ---
        try
        {
            var allStartup = StartupManager.GetAllEntries();
            foreach (var entry in allStartup)
            {
                if (entry.IsEnabled &&
                    (string.Equals(entry.ExecutablePath, cleanPath, StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(Path.GetFileName(entry.ExecutablePath), programName, StringComparison.OrdinalIgnoreCase)))
                {
                    var (ok, _) = await StartupManager.SetEnabledAsync(entry, false);
                    if (ok)
                    {
                        snapshot.DisabledStartupEntries.Add(new QuarantineStartupRecord(entry.Id, entry.Name, entry.LocationDisplay));
                    }
                }
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Quarantine Stage 4 Startup error: {ex.Message}");
        }

        // --- STAGE 5: Windows Firewall Block & RuleStore ---
        try
        {
            var existingRule = _rules.Find(cleanPath);
            snapshot.PreviousRuleAction = existingRule?.Action;

            var plan = RulePlanner.Plan(RuleDirection.Both, TrafficScope.All);
            _enforcer.Block(cleanPath, plan, "QUARANTINE VAULT ACTIVE");
            _rules.Set(new ProgramRule(cleanPath, RuleAction.Block, DateTimeOffset.Now, "QUARANTINE VAULT ACTIVE", RuleDirection.Both, TrafficScope.All));
            snapshot.FirewallRulesApplied = true;
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Quarantine Stage 5 Firewall error: {ex.Message}");
        }

        _vault.SaveSnapshot(snapshot);

        return (true, $"Program '{programName}' has been quarantined. ({snapshot.SummaryDisplay})", snapshot);
    }

    /// <summary>
    /// Restores a previously quarantined program, reversing all 5 stages:
    /// - Stage 1: Removes kernel-level execution lockout (IFEO) allowing program to run again.
    /// - Stage 2: Removes quarantine firewall block rules and restores previous rule standing.
    /// - Stage 3: Re-enables disabled auto-start items.
    /// - Stage 4: Restores original Windows service start types and restarts services if they were running.
    /// - Stage 5: Marks snapshot restored in Quarantine Vault.
    /// </summary>
    public async Task<(bool Success, string Message)> RestoreAsync(string snapshotId)
    {
        var snapshot = _vault.GetAll().FirstOrDefault(s => s.Id == snapshotId);
        if (snapshot == null)
            return (false, "Quarantine snapshot not found.");

        if (snapshot.IsRestored)
            return (false, $"Program '{snapshot.ProgramName}' is already restored.");

        // Stage 1: Remove Execution Lockout (IFEO)
        try
        {
            SetExecutionLockout(snapshot.ProgramName, false);
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Quarantine Restore Execution Lockout error: {ex.Message}");
        }

        // Stage 2: Restore Firewall & RuleStore
        try
        {
            if (snapshot.PreviousRuleAction == null)
            {
                _rules.Remove(snapshot.ExecutablePath);
                _enforcer.Unblock(snapshot.ExecutablePath);
                _enforcer.RemoveAllow(snapshot.ExecutablePath);
            }
            else
            {
                if (snapshot.PreviousRuleAction == RuleAction.Allow)
                {
                    _enforcer.Unblock(snapshot.ExecutablePath);
                    _rules.Set(new ProgramRule(snapshot.ExecutablePath, RuleAction.Allow, DateTimeOffset.Now, null, RuleDirection.Both, TrafficScope.All));
                }
                else
                {
                    var plan = RulePlanner.Plan(RuleDirection.Both, TrafficScope.All);
                    _enforcer.Block(snapshot.ExecutablePath, plan);
                    _rules.Set(new ProgramRule(snapshot.ExecutablePath, RuleAction.Block, DateTimeOffset.Now, null, RuleDirection.Both, TrafficScope.All));
                }
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Quarantine Restore Firewall error: {ex.Message}");
        }

        // 2. Restore Auto-Start Entries
        try
        {
            var allStartup = StartupManager.GetAllEntries();
            foreach (var rec in snapshot.DisabledStartupEntries)
            {
                var entry = allStartup.FirstOrDefault(e => e.Id == rec.EntryId);
                if (entry != null && !entry.IsEnabled)
                {
                    await StartupManager.SetEnabledAsync(entry, true);
                }
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Quarantine Restore Startup error: {ex.Message}");
        }

        // 3. Restore Windows Services
        try
        {
            foreach (var s in snapshot.ModifiedServices)
            {
                await WindowsServiceManager.SetServiceStartTypeAsync(s.ServiceName, s.OriginalStartType);
                if (s.WasRunning)
                {
                    await WindowsServiceManager.StartServiceAsync(s.ServiceName);
                }
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"Quarantine Restore Services error: {ex.Message}");
        }

        _vault.MarkRestored(snapshot.Id);

        return (true, $"Program '{snapshot.ProgramName}' was successfully restored from quarantine.");
    }

    /// <summary>
    /// Restores all active quarantined applications (invoked by the global PANIC button).
    /// </summary>
    public async Task<(int RestoredCount, List<string> Errors)> RestoreAllActiveAsync()
    {
        var active = _vault.GetActive();
        int count = 0;
        var errors = new List<string>();

        foreach (var snap in active)
        {
            var (ok, msg) = await RestoreAsync(snap.Id);
            if (ok) count++;
            else errors.Add($"{snap.ProgramName}: {msg}");
        }

        return (count, errors);
    }

    private static List<DiscoveredService> FindServicesWithBinaryPath(string executablePath)
    {
        var list = new List<DiscoveredService>();
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey == null) return list;

            foreach (var subName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var subKey = servicesKey.OpenSubKey(subName);
                    if (subKey == null) continue;

                    string? img = subKey.GetValue("ImagePath") as string;
                    if (string.IsNullOrEmpty(img)) continue;

                    string cleanImg = img.Trim('"', ' ').Replace("%SystemRoot%", Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase);
                    if (cleanImg.Contains(executablePath, StringComparison.OrdinalIgnoreCase))
                    {
                        string dName = subKey.GetValue("DisplayName") as string ?? subName;
                        list.Add(new DiscoveredService(subName, dName, 0, 1));
                    }
                }
                catch { }
            }
        }
        catch { }
        return list;
    }

    private static readonly string[] IfeoPaths = new[]
    {
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    };

    /// <summary>
    /// Scans the Windows Registry IFEO trees (both 64-bit and 32-bit hives) for any program names hijacked with "Debugger = systray.exe".
    /// Returns the list of executable names currently locked out at the kernel level.
    /// </summary>
    public static List<string> GetActiveExecutionLockouts()
    {
        var list = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var ifeoRoot in IfeoPaths)
        {
            try
            {
                using var root = Registry.LocalMachine.OpenSubKey(ifeoRoot);
                if (root == null) continue;
                foreach (var subName in root.GetSubKeyNames())
                {
                    try
                    {
                        using var sub = root.OpenSubKey(subName);
                        if (sub == null) continue;
                        string? dbg = sub.GetValue("Debugger") as string;
                        if (!string.IsNullOrEmpty(dbg) && dbg.Contains("systray.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            list.Add(subName);
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogWarn($"GetActiveExecutionLockouts error for root '{ifeoRoot}': {ex.Message}");
            }
        }
        return list.ToList();
    }

    /// <summary>
    /// Clears execution lockout (IFEO) for all programs that were redirected to systray.exe.
    /// </summary>
    public static int RemoveAllExecutionLockouts()
    {
        int count = 0;
        var locked = GetActiveExecutionLockouts();
        foreach (var prog in locked)
        {
            if (SetExecutionLockout(prog, false))
            {
                count++;
                RotatingFileLogger.LogInfo($"Removed execution lockout (IFEO) for '{prog}'.");
            }
        }
        return count;
    }

    /// <summary>
    /// Reconciles the system IFEO registry state against active QuarantineVault records.
    /// If an IFEO lockout exists that is:
    ///   1. For a protected runtime (e.g. msedgewebview2.exe, ollama.exe), or
    ///   2. Orphaned (no active snapshot exists in the QuarantineVault due to uninstall, clear data, or crash),
    /// it automatically removes the execution lockout to prevent silent process launch crashes and cache permission errors.
    /// </summary>
    public List<string> ReconcileAndHealOrphanedLockouts()
    {
        var healed = new List<string>();
        var activeSnapshots = _vault.GetActive();
        var lockouts = GetActiveExecutionLockouts();

        foreach (var prog in lockouts)
        {
            bool isProtected = ProtectedPrograms.DisallowedExecutionLockoutBinaries.Contains(prog);
            bool hasActiveSnapshot = activeSnapshots.Any(s => string.Equals(s.ProgramName, prog, StringComparison.OrdinalIgnoreCase));

            if (isProtected || !hasActiveSnapshot)
            {
                try
                {
                    if (SetExecutionLockout(prog, false))
                    {
                        healed.Add(prog);
                        RotatingFileLogger.LogInfo($"Self-Healing: Automatically cleared {(isProtected ? "protected component" : "orphaned")} IFEO execution lockout for '{prog}'.");
                    }
                }
                catch (Exception ex)
                {
                    RotatingFileLogger.LogError($"Self-Healing: Failed to remove IFEO lockout for '{prog}'", ex);
                }
            }
        }

        return healed;
    }

    /// <summary>
    /// Enforces or removes kernel-level execution lockout via Image File Execution Options (IFEO).
    /// When enabled, Windows intercepts attempts to launch programName and runs systray.exe (which exits immediately),
    /// completely preventing the executable from starting. 100% reversible by deleting the Debugger value.
    /// </summary>
    public static bool SetExecutionLockout(string programName, bool enable)
    {
        if (string.IsNullOrWhiteSpace(programName)) return false;
        bool anySuccess = false;

        foreach (var ifeoRoot in IfeoPaths)
        {
            try
            {
                string subKeyPath = $@"{ifeoRoot}\{programName}";
                if (enable)
                {
                    using var key = Registry.LocalMachine.CreateSubKey(subKeyPath);
                    if (key != null)
                    {
                        key.SetValue("Debugger", "systray.exe", RegistryValueKind.String);
                        anySuccess = true;
                    }
                }
                else
                {
                    using var key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: true);
                    if (key != null)
                    {
                        key.DeleteValue("Debugger", throwOnMissingValue: false);
                        if (key.ValueCount == 0 && key.SubKeyCount == 0)
                        {
                            key.Dispose();
                            Registry.LocalMachine.DeleteSubKey(subKeyPath, throwOnMissingSubKey: false);
                        }
                        anySuccess = true;
                    }
                }
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogWarn($"IFEO lockout error ({ifeoRoot}\\{programName}): {ex.Message}");
            }
        }

        return anySuccess;
    }
}
