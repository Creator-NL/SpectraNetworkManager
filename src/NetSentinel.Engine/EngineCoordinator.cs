using NetSentinel.Core;
using NetSentinel.Core.Ipc;
using NetSentinel.Platform.Windows;
using NetSentinel.Sinkhole;

namespace NetSentinel.Engine;

/// <summary>
/// Core background coordinator for NetSentinel.Engine.
/// Manages the connection monitor, rule enforcement, strict-mode watchdog,
/// DNS sinkhole, security log reader, and IPC communications.
/// </summary>
public sealed class EngineCoordinator : IAsyncDisposable, IDisposable
{
    private readonly bool _safeMode;
    private readonly ConnectionMonitor _monitor;
    private readonly RuleStore _rules;
    private readonly WindowsFirewallEnforcer _enforcer;
    private readonly StrictModeStore _strict;
    private readonly FirewallBlockLog _blockLog;
    private readonly DnsService _dns;
    private readonly SystemDnsSwitchManager _dnsSwitch;
    private readonly IpcServer _ipcServer;

    private readonly CancellationTokenSource _cts = new();
    private Task? _monitorLoopTask;
    private Task? _blockLogLoopTask;

    // Strict mode auto-revert state
    private readonly object _strictLock = new();
    private CancellationTokenSource? _strictCountdownCts;
    private Task? _strictCountdownTask;

    private bool _disposed;

    public bool IsSafeMode => _safeMode;
    public StrictPhase StrictPhase => _strict.State.Phase;
    public DnsService Dns => _dns;

    public EngineCoordinator(bool safeMode = false)
    {
        _safeMode = safeMode;

        _rules = new RuleStore(EngineStoragePaths.RulesPath);
        _enforcer = new WindowsFirewallEnforcer();
        _strict = new StrictModeStore(EngineStoragePaths.StrictModePath);
        _blockLog = new FirewallBlockLog();

        _monitor = new ConnectionMonitor(new IpHelperConnectionSource(), new ProcessResolver());

        _dns = new DnsService(
            EngineStoragePaths.DnsSettingsPath,
            EngineStoragePaths.BlocklistsDirectory,
            null,
            EngineStoragePaths.DnsHistoryPath);

        _dnsSwitch = new SystemDnsSwitchManager(
            new SystemDnsSwitchStore(EngineStoragePaths.DnsBackupPath),
            null,
            () => _dns.LocalEndPoint);

        _ipcServer = new IpcServer(
            IpcConstants.PipeName,
            pipeName => WindowsPipeSecurityHelper.CreateSecuredServerStream(pipeName));

        _ipcServer.RequestHandler = HandleIpcRequestAsync;

        // Wire DNS queries to IPC broadcast
        _dns.Queried += entry =>
        {
            _ = _ipcServer.BroadcastEventAsync(IpcConstants.Events.DnsQuery, entry);
        };
    }

    public async Task StartAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Recover any unconfirmed or crash-leftover state
        await RecoverStateOnStartupAsync();

        // Start IPC server listener
        _ipcServer.Start();

        // Start DNS sinkhole if auto-start is configured and not in safe mode
        if (!_safeMode && _dns.Settings.AutoStart)
        {
            try
            {
                await _dns.StartAsync();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[DNS] Failed to auto-start DNS sinkhole: {ex.Message}");
            }
        }

        // Start background polling loops
        _monitorLoopTask = Task.Run(MonitorLoopAsync, ct);
        _blockLogLoopTask = Task.Run(BlockLogLoopAsync, ct);
    }

    private async Task RecoverStateOnStartupAsync()
    {
        if (_strict.State.Phase == StrictPhase.Pending || _safeMode)
        {
            Console.WriteLine("[StrictMode] Pending or safe-mode detected at engine startup. Rolling back firewall defaults...");
            await DisableStrictInternalAsync();
        }
    }

    private async Task MonitorLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                if (_ipcServer.ConnectedClientCount > 0)
                {
                    var tick = _monitor.Poll();
                    await _ipcServer.BroadcastEventAsync(IpcConstants.Events.MonitorTick, tick, _cts.Token);
                }
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested) { break; }
            catch (Exception) { }

            try { await Task.Delay(1000, _cts.Token); } catch { }
        }
    }

    private async Task BlockLogLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                if (_ipcServer.ConnectedClientCount > 0)
                {
                    var blocks = _blockLog.ReadRecent(TimeSpan.FromSeconds(5), 10);
                    if (blocks.Count > 0)
                    {
                        await _ipcServer.BroadcastEventAsync(IpcConstants.Events.BlockDetected, blocks, _cts.Token);
                    }
                }
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested) { break; }
            catch (Exception) { }

            try { await Task.Delay(2000, _cts.Token); } catch { }
        }
    }

    private async Task<IpcMessage> HandleIpcRequestAsync(IpcMessage request)
    {
        try
        {
            return request.Action switch
            {
                IpcConstants.Actions.Ping => IpcMessage.CreateResponse(request, new { Status = "OK", Timestamp = DateTimeOffset.UtcNow }),
                IpcConstants.Actions.GetEngineStatus => IpcMessage.CreateResponse(request, GetEngineStatus()),
                IpcConstants.Actions.GetSnapshot => IpcMessage.CreateResponse(request, _monitor.Poll()),
                IpcConstants.Actions.GetRules => IpcMessage.CreateResponse(request, _rules.All),
                IpcConstants.Actions.AddRule => await HandleAddRuleAsync(request),
                IpcConstants.Actions.RemoveRule => await HandleRemoveRuleAsync(request),
                IpcConstants.Actions.ClearRules => await HandleClearRulesAsync(request),

                IpcConstants.Actions.SetStrictMode => await HandleSetStrictModeAsync(request),
                IpcConstants.Actions.ConfirmStrictMode => await HandleConfirmStrictModeAsync(request),
                IpcConstants.Actions.CancelStrictMode => await HandleCancelStrictModeAsync(request),
                IpcConstants.Actions.Panic => await HandlePanicAsync(request),

                IpcConstants.Actions.StartDns => await HandleStartDnsAsync(request),
                IpcConstants.Actions.StopDns => HandleStopDns(request),
                IpcConstants.Actions.GetDnsSettings => IpcMessage.CreateResponse(request, _dns.Settings),
                IpcConstants.Actions.ApplyDnsSettings => await HandleApplyDnsSettingsAsync(request),
                IpcConstants.Actions.PauseDnsBlocking => HandlePauseDnsBlocking(request),
                IpcConstants.Actions.ResumeDnsBlocking => HandleResumeDnsBlocking(request),
                IpcConstants.Actions.UpdateBlocklists => await HandleUpdateBlocklistsAsync(request),

                IpcConstants.Actions.GetDnsSwitchAdapters => await HandleGetDnsAdaptersAsync(request),
                IpcConstants.Actions.ApplyDnsSwitch => await HandleApplyDnsSwitchAsync(request),
                IpcConstants.Actions.RestoreDnsSwitch => await HandleRestoreDnsSwitchAsync(request),

                _ => IpcMessage.CreateErrorResponse(request, $"Unknown IPC action '{request.Action}'.")
            };
        }
        catch (Exception ex)
        {
            return IpcMessage.CreateErrorResponse(request, ex.Message);
        }
    }

    private object GetEngineStatus()
    {
        var stats = _dns.Activity.Snapshot();
        return new
        {
            SafeMode = _safeMode,
            DnsRunning = _dns.IsRunning,
            DnsListenEndPoint = _dns.LocalEndPoint?.ToString(),
            DnsTotalQueries = stats.Total,
            DnsBlockedQueries = stats.Blocked,
            DnsCachedQueries = stats.Cached,
            DnsForwardedQueries = stats.Forwarded,
            DnsBlocklistCount = _dns.BlockedDomainCount,
            StrictPhase = _strict.State.Phase.ToString(),
            ClientCount = _ipcServer.ConnectedClientCount
        };
    }

    private async Task<IpcMessage> HandleAddRuleAsync(IpcMessage request)
    {
        var rule = request.DeserializePayload<ProgramRule>();
        if (rule == null) return IpcMessage.CreateErrorResponse(request, "Invalid ProgramRule payload.");

        _rules.Set(rule);
        if (!_safeMode)
        {
            if (rule.Action == RuleAction.Block)
            {
                var plan = RulePlanner.Plan(rule.Direction, rule.Scope);
                await Task.Run(() => _enforcer.Block(rule.Path, plan));
            }
            else
            {
                await Task.Run(() => _enforcer.Unblock(rule.Path));
            }
        }

        return IpcMessage.CreateResponse(request, true);
    }

    private async Task<IpcMessage> HandleRemoveRuleAsync(IpcMessage request)
    {
        var path = request.DeserializePayload<string>();
        if (string.IsNullOrEmpty(path)) return IpcMessage.CreateErrorResponse(request, "Path is required.");

        _rules.Remove(path);
        if (!_safeMode)
        {
            await Task.Run(() => _enforcer.Unblock(path));
        }

        return IpcMessage.CreateResponse(request, true);
    }

    private async Task<IpcMessage> HandleClearRulesAsync(IpcMessage request)
    {
        _rules.RemoveWhere(_ => true);
        if (!_safeMode)
        {
            await Task.Run(() => _enforcer.RemoveAll());
        }

        return IpcMessage.CreateResponse(request, true);
    }

    private Task<IpcMessage> HandleSetStrictModeAsync(IpcMessage request)
    {
        lock (_strictLock)
        {
            if (_safeMode)
                return Task.FromResult(IpcMessage.CreateErrorResponse(request, "Strict mode cannot be enabled while in safe mode."));

            var previous = _enforcer.ReadDefaultOutbound();
            var deadline = DateTimeOffset.UtcNow.AddSeconds(60);

            // Save pending state first (undo-first safety pattern)
            _strict.Save(new StrictModeState(StrictPhase.Pending, deadline, previous));

            // Plan & apply essential allows
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var allows = StrictModePlanner.Plan(winDir, Environment.ProcessPath, _rules.All.Where(r => r.Action == RuleAction.Allow).Select(r => r.Path));
            foreach (var allow in allows)
            {
                _enforcer.Allow(allow);
            }

            // Block outbound by default
            _enforcer.SetDefaultOutbound(ProfileDefaults.AllBlock);

            // Start engine-side auto-revert countdown watchdog
            _strictCountdownCts?.Cancel();
            _strictCountdownCts = new CancellationTokenSource();
            _strictCountdownTask = Task.Run(() => StrictModeCountdownLoopAsync(_strictCountdownCts.Token));

            _ = _ipcServer.BroadcastEventAsync(IpcConstants.Events.StrictModeChanged, new { Phase = StrictPhase.Pending.ToString() });
            return Task.FromResult(IpcMessage.CreateResponse(request, new { Success = true, Deadline = deadline }));
        }
    }

    private async Task StrictModeCountdownLoopAsync(CancellationToken ct)
    {
        int remaining = 60;
        while (remaining > 0 && !ct.IsCancellationRequested)
        {
            await _ipcServer.BroadcastEventAsync(IpcConstants.Events.StrictModeTick, new { RemainingSeconds = remaining }, ct);
            try
            {
                await Task.Delay(1000, ct);
            }
            catch (OperationCanceledException)
            {
                return; // Confirmed or canceled
            }
            remaining--;
        }

        if (!ct.IsCancellationRequested)
        {
            Console.WriteLine("[StrictMode] Watchdog timeout: strict mode was not confirmed within 60 seconds. Reverting to safe defaults!");
            await DisableStrictInternalAsync();
        }
    }

    private Task<IpcMessage> HandleConfirmStrictModeAsync(IpcMessage request)
    {
        lock (_strictLock)
        {
            _strictCountdownCts?.Cancel();
            var current = _strict.State;
            _strict.Save(new StrictModeState(StrictPhase.Active, null, current.Previous));
            _ = _ipcServer.BroadcastEventAsync(IpcConstants.Events.StrictModeChanged, new { Phase = StrictPhase.Active.ToString() });
            return Task.FromResult(IpcMessage.CreateResponse(request, true));
        }
    }

    private async Task<IpcMessage> HandleCancelStrictModeAsync(IpcMessage request)
    {
        await DisableStrictInternalAsync();
        return IpcMessage.CreateResponse(request, true);
    }

    private async Task DisableStrictInternalAsync()
    {
        lock (_strictLock)
        {
            _strictCountdownCts?.Cancel();
        }

        var state = _strict.State;
        var restore = state.Previous ?? ProfileDefaults.StandardWindows;
        try
        {
            _enforcer.SetDefaultOutbound(restore);
            _enforcer.RemoveAllAllowRules();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[StrictMode] Error restoring firewall profile defaults: {ex.Message}");
        }

        _strict.Save(StrictModeState.Off);
        await _ipcServer.BroadcastEventAsync(IpcConstants.Events.StrictModeChanged, new { Phase = StrictPhase.Off.ToString() });
    }

    private async Task<IpcMessage> HandlePanicAsync(IpcMessage request)
    {
        Console.WriteLine("[Panic] Panic button pressed! Restoring all defaults and disarming blocks...");

        // 1. Restore DNS switch if active
        try
        {
            await _dnsSwitch.RevertAsync();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Panic] DNS restore error: {ex.Message}");
        }

        // 2. Rollback strict mode
        await DisableStrictInternalAsync();

        // 3. Remove all NetSentinel firewall rules
        try
        {
            _enforcer.RemoveAll();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Panic] Firewall rule removal error: {ex.Message}");
        }

        return IpcMessage.CreateResponse(request, new { Message = "All NetSentinel firewall rules and DNS alterations have been restored to Windows defaults." });
    }

    private async Task<IpcMessage> HandleStartDnsAsync(IpcMessage request)
    {
        await _dns.StartAsync();
        return IpcMessage.CreateResponse(request, new { Running = _dns.IsRunning, LocalEndPoint = _dns.LocalEndPoint?.ToString() });
    }

    private IpcMessage HandleStopDns(IpcMessage request)
    {
        _dns.Stop();
        return IpcMessage.CreateResponse(request, new { Running = _dns.IsRunning });
    }

    private async Task<IpcMessage> HandleApplyDnsSettingsAsync(IpcMessage request)
    {
        var settings = request.DeserializePayload<DnsSettings>();
        if (settings == null) return IpcMessage.CreateErrorResponse(request, "Invalid DnsSettings payload.");

        await _dns.ApplySettingsAsync(settings);
        return IpcMessage.CreateResponse(request, true);
    }

    private IpcMessage HandlePauseDnsBlocking(IpcMessage request)
    {
        var minutes = request.DeserializePayload<int>();
        if (minutes <= 0) minutes = 5;

        _dns.PauseBlocking(TimeSpan.FromMinutes(minutes));
        return IpcMessage.CreateResponse(request, new { PausedUntil = _dns.BlockingPausedUntil });
    }

    private IpcMessage HandleResumeDnsBlocking(IpcMessage request)
    {
        _dns.ResumeBlocking();
        return IpcMessage.CreateResponse(request, true);
    }

    private async Task<IpcMessage> HandleUpdateBlocklistsAsync(IpcMessage request)
    {
        var results = await _dns.UpdateListsAsync();
        return IpcMessage.CreateResponse(request, new { LoadedDomains = _dns.BlockedDomainCount, Results = results });
    }

    private async Task<IpcMessage> HandleGetDnsAdaptersAsync(IpcMessage request)
    {
        var adapters = await _dnsSwitch.GetAdaptersAsync();
        return IpcMessage.CreateResponse(request, adapters);
    }

    private async Task<IpcMessage> HandleApplyDnsSwitchAsync(IpcMessage request)
    {
        var indices = request.DeserializePayload<List<int>>();
        if (indices == null || indices.Count == 0) return IpcMessage.CreateErrorResponse(request, "No adapter indices provided.");

        await _dnsSwitch.ApplyAsync(indices, onlyLocal: false);
        return IpcMessage.CreateResponse(request, true);
    }

    private async Task<IpcMessage> HandleRestoreDnsSwitchAsync(IpcMessage request)
    {
        await _dnsSwitch.RevertAsync();
        return IpcMessage.CreateResponse(request, true);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
        _ipcServer.Dispose();
        _dns.Dispose();
        _dnsSwitch.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();

        if (_monitorLoopTask != null) try { await _monitorLoopTask.ConfigureAwait(false); } catch { }
        if (_blockLogLoopTask != null) try { await _blockLogLoopTask.ConfigureAwait(false); } catch { }
        if (_strictCountdownTask != null) try { await _strictCountdownTask.ConfigureAwait(false); } catch { }

        await _ipcServer.DisposeAsync().ConfigureAwait(false);
        _dns.Dispose();
        _dnsSwitch.Dispose();
        _cts.Dispose();
    }
}
