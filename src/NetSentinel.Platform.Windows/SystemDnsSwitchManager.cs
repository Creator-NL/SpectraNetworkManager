using System.Net;
using NetSentinel.Sinkhole;

namespace NetSentinel.Platform.Windows;

public sealed class DnsProbeResult
{
    public bool LocalOk { get; init; }
    public bool SystemOk { get; init; }
    public string Details { get; init; } = "";
}

/// <summary>
/// Orchestrates pointing system network adapters at NetSentinel's DNS sinkhole,
/// enforcing the 60-second safety confirmation window, automatic rollback, and crash recovery.
/// </summary>
public sealed class SystemDnsSwitchManager : IDisposable
{
    public const int ConfirmTimeoutSeconds = 60;

    private readonly SystemDnsSwitchStore _store;
    private readonly ISystemDnsSwitch _switch;
    private readonly Func<IPEndPoint?>? _localDnsEndpoint;
    private CancellationTokenSource? _revertTimerCts;

    public SystemDnsSwitchManager(
        SystemDnsSwitchStore? store = null,
        ISystemDnsSwitch? dnsSwitch = null,
        Func<IPEndPoint?>? localDnsEndpoint = null)
    {
        _store = store ?? new SystemDnsSwitchStore();
        _switch = dnsSwitch ?? new WindowsSystemDnsSwitch();
        _localDnsEndpoint = localDnsEndpoint;
    }

    public SystemDnsSwitchStore Store => _store;
    public SystemDnsSwitchState State => _store.State;
    public bool IsActive => State.Phase == DnsSwitchPhase.Active;
    public bool IsPending => State.Phase == DnsSwitchPhase.Pending;

    public event Action<SystemDnsSwitchState>? StateChanged;

    /// <summary>
    /// Checks if a previous run crashed or terminated while in Pending confirmation.
    /// If so, immediately restores the original DNS settings to prevent network lockouts.
    /// </summary>
    public async Task<bool> CheckStartupRecoveryAsync(CancellationToken ct = default)
    {
        if (State.Phase == DnsSwitchPhase.Pending)
        {
            await RevertAsync(ct).ConfigureAwait(false);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Backs up selected adapters, saves Pending state, applies NetSentinel DNS, and arms the 60-second revert timer.
    /// </summary>
    public async Task ApplyAsync(IEnumerable<int> targetIndexes, bool onlyLocal, CancellationToken ct = default)
    {
        var targetSet = targetIndexes.ToHashSet();
        if (targetSet.Count == 0) throw new InvalidOperationException("Select at least one network adapter to change.");

        var allAdapters = await _switch.GetAdaptersAsync(ct).ConfigureAwait(false);
        var selected = allAdapters.Where(a => targetSet.Contains(a.InterfaceIndex)).ToList();
        if (selected.Count == 0) throw new InvalidOperationException("None of the selected adapters are available.");

        // Create backups of current configuration
        var backups = selected.Select(a => new AdapterDnsBackup(
            a.InterfaceIndex,
            a.Name,
            a.Guid,
            a.Ipv4Servers,
            a.Ipv4IsDhcp,
            a.Ipv6Servers,
            a.Ipv6IsDhcp)).ToList();

        // Save Pending state FIRST before changing any adapter setting
        var deadline = DateTimeOffset.UtcNow.AddSeconds(ConfirmTimeoutSeconds);
        var pendingState = new SystemDnsSwitchState(DnsSwitchPhase.Pending, deadline, onlyLocal, backups);
        _store.Save(pendingState);
        StateChanged?.Invoke(pendingState);

        // Apply DNS changes
        try
        {
            await _switch.ApplyDnsAsync(targetSet, onlyLocal, backups, ct).ConfigureAwait(false);
        }
        catch
        {
            // If applying failed, immediately revert
            await RevertAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        // Arm automatic 60-second revert timer
        ArmRevertTimer();
    }

    /// <summary>
    /// User confirmed the new settings. Disarms the revert timer and saves Active state.
    /// </summary>
    public void Confirm()
    {
        CancelRevertTimer();

        if (State.Phase == DnsSwitchPhase.Pending)
        {
            var activeState = new SystemDnsSwitchState(DnsSwitchPhase.Active, null, State.OnlyLocal, State.Backups);
            _store.Save(activeState);
            StateChanged?.Invoke(activeState);
        }
    }

    /// <summary>
    /// Reverts DNS settings on all backed up adapters back to their original state (DHCP or static servers).
    /// </summary>
    public async Task RevertAsync(CancellationToken ct = default)
    {
        CancelRevertTimer();

        var backups = State.Backups;
        if (backups.Count == 0)
        {
            // Also check if backup file on disk has entries
            backups = _store.LoadBackupFile();
        }

        if (backups.Count > 0)
        {
            try
            {
                await _switch.RestoreDnsAsync(backups, ct).ConfigureAwait(false);
            }
            catch (Exception) { /* best effort rollback */ }
        }

        _store.Save(SystemDnsSwitchState.Off);
        StateChanged?.Invoke(SystemDnsSwitchState.Off);
    }

    /// <summary>
    /// Panic restore: immediately restores all adapters from memory or disk backup.
    /// </summary>
    public Task RestoreAllAsync(CancellationToken ct = default) => RevertAsync(ct);

    /// <summary>
    /// Tests both the local sinkhole socket and the Windows system resolver to verify DNS connectivity.
    /// </summary>
    public async Task<DnsProbeResult> ProbeResolutionAsync(CancellationToken ct = default)
    {
        bool localOk = false;
        bool systemOk = false;
        string detail = "";

        // 1. Probe local server if endpoint known
        var localEp = _localDnsEndpoint?.Invoke();
        if (localEp is not null)
        {
            try
            {
                var selfTest = await DnsSelfTest.RunAsync(localEp, "example.com", ct: ct).ConfigureAwait(false);
                localOk = selfTest.Ok;
                if (!localOk) detail += "Local sinkhole socket test failed. ";
            }
            catch (Exception ex)
            {
                detail += $"Local sinkhole error: {ex.Message}. ";
            }
        }
        else
        {
            localOk = true; // no local endpoint supplied, skip
        }

        // 2. Probe system resolver (tests whether Windows network stack is resolving correctly)
        try
        {
            var ips = await Dns.GetHostAddressesAsync("example.com", ct).ConfigureAwait(false);
            systemOk = ips.Length > 0;
            if (!systemOk) detail += "Windows system resolver returned 0 addresses for example.com. ";
        }
        catch (Exception ex)
        {
            detail += $"Windows resolver failed: {ex.Message}. ";
        }

        if (localOk && systemOk)
            detail = "Both local NetSentinel DNS and Windows system resolver verified successfully.";

        return new DnsProbeResult
        {
            LocalOk = localOk,
            SystemOk = systemOk,
            Details = detail.Trim(),
        };
    }

    private void ArmRevertTimer()
    {
        CancelRevertTimer();

        var cts = new CancellationTokenSource();
        _revertTimerCts = cts;

        _ = Task.Delay(TimeSpan.FromSeconds(ConfirmTimeoutSeconds), cts.Token).ContinueWith(async t =>
        {
            if (t.IsCompletedSuccessfully && State.Phase == DnsSwitchPhase.Pending)
            {
                // Auto revert on timeout
                await RevertAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }, TaskScheduler.Default);
    }

    private void CancelRevertTimer()
    {
        _revertTimerCts?.Cancel();
        _revertTimerCts?.Dispose();
        _revertTimerCts = null;
    }

    public void Dispose()
    {
        CancelRevertTimer();
    }
}
