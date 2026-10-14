using System.Net;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Core.Ipc;
using SpectraNetworkManager.Platform.Windows;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Engine;

/// <summary>
/// Core background coordinator for SpectraNetworkManager.Engine.
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
    private readonly IBlockEventSource _blockLog;
    private readonly DnsService _dns;
    private readonly SystemDnsSwitchManager _dnsSwitch;
    private readonly NetworkHistoryDatabase _historyDb;
    private readonly EtwBandwidthMonitor _etw;
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
        var wfpSource = new NativeWfpBlockEventSubscriber();
        wfpSource.BlockDetected += ev =>
        {
            if (_ipcServer?.ConnectedClientCount > 0)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var server = _ipcServer;
                        if (server != null)
                        {
                            await server.BroadcastEventAsync(IpcConstants.Events.BlockDetected, new List<BlockEvent> { ev }, _cts.Token);
                        }
                    }
                    catch { }
                });
            }
        };
        _blockLog = wfpSource;

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

        _historyDb = new NetworkHistoryDatabase(EngineStoragePaths.NetworkHistoryPath);
        _etw = new EtwBandwidthMonitor();

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

        // Start ETW bandwidth monitor if elevated on Windows
        if (OperatingSystem.IsWindows() && !_safeMode)
        {
            _etw.TryStart();
        }

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
                var tick = _monitor.Poll();
                var bwSamples = _etw.HarvestInterval(1.0);
                var now = DateTimeOffset.UtcNow;

                // Record connections seen to persistent SQLite
                foreach (var conn in tick.Connections)
                {
                    if (conn.Process?.Path != null && conn.Connection.Remote != null)
                    {
                        _historyDb.RecordConnection(
                            conn.Process.Path,
                            conn.Connection.Remote.Address.ToString(),
                            conn.Connection.Remote.Port,
                            conn.Connection.Protocol.ToString(),
                            now);
                    }
                }

                // Record per-process bandwidth to persistent SQLite
                if (bwSamples.Count > 0)
                {
                    foreach (var sample in bwSamples.Values)
                    {
                        var proc = tick.Connections.FirstOrDefault(c => c.Connection.ProcessId == sample.Pid)?.Process;
                        if (proc?.Path != null)
                        {
                            _historyDb.RecordBandwidth(now, proc.Path, sample.BytesReceivedPerSec, sample.BytesSentPerSec);
                        }
                    }
                }

                if (_ipcServer.ConnectedClientCount > 0)
                {
                    await _ipcServer.BroadcastEventAsync(IpcConstants.Events.MonitorTick, tick, _cts.Token);
                    if (bwSamples.Count > 0)
                    {
                        await _ipcServer.BroadcastEventAsync(IpcConstants.Events.BandwidthUpdate, bwSamples.Values.ToList(), _cts.Token);
                    }
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
                // Only poll fallback if native real-time WFP subscription is not active
                if (!_blockLog.IsNativeSubscribed && _ipcServer.ConnectedClientCount > 0)
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
                IpcConstants.Actions.ConfirmDnsSwitch => HandleConfirmDnsSwitch(request),
                IpcConstants.Actions.RestoreDnsSwitch => await HandleRestoreDnsSwitchAsync(request),

                IpcConstants.Actions.GetTopTalkers => await HandleGetTopTalkersAsync(request),
                IpcConstants.Actions.GetConnectionHistory => await HandleGetConnectionHistoryAsync(request),

                IpcConstants.Actions.TerminateConnections => HandleTerminateConnections(request),
                IpcConstants.Actions.TerminateProcess => HandleTerminateProcess(request),

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

        // 3. Remove all SpectraNetworkManager firewall rules
        try
        {
            _enforcer.RemoveAll();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Panic] Firewall rule removal error: {ex.Message}");
        }

        return IpcMessage.CreateResponse(request, new { Message = "All SpectraNetworkManager firewall rules and DNS alterations have been restored to Windows defaults." });
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

    private IpcMessage HandleConfirmDnsSwitch(IpcMessage request)
    {
        _dnsSwitch.Confirm();
        return IpcMessage.CreateResponse(request, true);
    }

    private async Task<IpcMessage> HandleRestoreDnsSwitchAsync(IpcMessage request)
    {
        await _dnsSwitch.RevertAsync().ConfigureAwait(false);
        return IpcMessage.CreateResponse(request, true);
    }

    private async Task<IpcMessage> HandleGetTopTalkersAsync(IpcMessage request)
    {
        var hours = request.DeserializePayload<int>();
        if (hours <= 0) hours = 24;
        var top = await _historyDb.GetTopTalkersAsync(TimeSpan.FromHours(hours)).ConfigureAwait(false);
        return IpcMessage.CreateResponse(request, top);
    }

    private async Task<IpcMessage> HandleGetConnectionHistoryAsync(IpcMessage request)
    {
        var limit = request.DeserializePayload<int>();
        if (limit <= 0) limit = 300;
        var list = await _historyDb.GetRecentConnectionsAsync(limit).ConfigureAwait(false);
        return IpcMessage.CreateResponse(request, list);
    }

    private IpcMessage HandleTerminateConnections(IpcMessage request)
    {
        var terminator = new TcpConnectionTerminator();
        int closed = 0;
        var payload = request.DeserializePayload<TerminateConnectionsRequest>();
        if (payload is not null)
        {
            if (payload.Pid.HasValue && payload.Pid.Value > 0)
            {
                closed += terminator.TerminateConnectionsForPid(payload.Pid.Value);
            }
            else if (!string.IsNullOrWhiteSpace(payload.ProgramPath))
            {
                closed += terminator.TerminateConnectionsForProgram(payload.ProgramPath);
            }
            else if (!string.IsNullOrWhiteSpace(payload.LocalEndPoint) && !string.IsNullOrWhiteSpace(payload.RemoteEndPoint))
            {
                if (IPEndPoint.TryParse(payload.LocalEndPoint, out var local) &&
                    IPEndPoint.TryParse(payload.RemoteEndPoint, out var remote))
                {
                    if (terminator.TerminateConnection(local, remote)) closed++;
                }
            }
        }
        return IpcMessage.CreateResponse(request, new TerminateConnectionsResult(closed, true));
    }

    private IpcMessage HandleTerminateProcess(IpcMessage request)
    {
        var payload = request.DeserializePayload<TerminateProcessRequest>();
        bool killed = false;
        if (payload is not null && payload.Pid > 0)
        {
            killed = TcpConnectionTerminator.KillProcess(payload.Pid);
        }
        return IpcMessage.CreateResponse(request, new TerminateProcessResult(killed, killed));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
        _etw.Dispose();
        _historyDb.Dispose();
        _ipcServer.Dispose();
        _dns.Dispose();
        _dnsSwitch.Dispose();
        _blockLog.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();

        if (_monitorLoopTask != null) try { await _monitorLoopTask.ConfigureAwait(false); } catch { }
        if (_blockLogLoopTask != null) try { await _blockLogLoopTask.ConfigureAwait(false); } catch { }
        if (_strictCountdownTask != null) try { await _strictCountdownTask.ConfigureAwait(false); } catch { }

        _etw.Dispose();
        await _historyDb.DisposeAsync().ConfigureAwait(false);
        await _ipcServer.DisposeAsync().ConfigureAwait(false);
        _dns.Dispose();
        _dnsSwitch.Dispose();
        _blockLog.Dispose();
        _cts.Dispose();
    }
}
