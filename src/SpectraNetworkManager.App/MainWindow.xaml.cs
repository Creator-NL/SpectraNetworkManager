using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Core.Ipc;
using SpectraNetworkManager.Platform.Windows;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Ui;

public partial class MainWindow : Window
{
    private const int MaxEventLines = 300;

    private static readonly ProcessResolver _processResolver = new();
    private readonly ConnectionMonitor _monitor = new(new IpHelperConnectionSource(), _processResolver);
    private readonly IBlockEventSource _blockLog = new NativeWfpBlockEventSubscriber();
    private readonly ReverseDnsCache _dns = new();
    private readonly RuleStore _rules = new(RuleStore.DefaultPath);
    private readonly WindowsFirewallEnforcer _enforcer = new();
    private readonly LearningTracker _learning = new();
    private readonly AuthenticodeVerifier _signatures = new(new SignatureCache(SignatureCache.DefaultPath));
    private readonly Dictionary<string, (ProgramSummary Summary, DateTimeOffset Since)> _awaiting = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _alarmed = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<ConnectionKey, ConnectionRow> _rows = new();
    private readonly Dictionary<string, ProgramRow> _programRows = new(StringComparer.OrdinalIgnoreCase);
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly ICollectionView _rowsView;
    private readonly ICollectionView _programsView;
    private readonly ICollectionView _startupView;
    private readonly bool _isAdmin = IsAdministrator();
    private DnsRow? _inspectedDnsRow;
    private bool _isUpdatingDnsRows;

    // Ask mode: programs waiting for an Allow / Block answer
    private readonly Queue<ProgramSummary> _askQueue = new();
    private readonly HashSet<string> _askQueued = new(StringComparer.OrdinalIgnoreCase);
    private ProgramSummary? _askCurrent;

    private IReadOnlyList<ConnectionView> _lastConnections = Array.Empty<ConnectionView>();
    private IpcClient? _engineClient;
    private bool _busy;

    private readonly NetworkHistoryDatabase _historyDb = new();
    private readonly EtwBandwidthMonitor _etw = new();
    private readonly EtwDnsClientMonitor _dnsEtw = new();
    private System.Windows.Forms.NotifyIcon? _trayIcon;
    private bool _isExiting;
    private bool _trayBalloonShown;
    private int _trafficHours = 1;
    private readonly AppSettingsStore _appSettings = new();
    private readonly UpdateChecker _updateChecker = new();
    private UpdateCheckResult? _lastUpdateResult;
    private NetworkPromptToastWindow? _promptToast;
    private System.Windows.Forms.ToolStripMenuItem? _trayAlwaysOnTopItem;
    private System.Windows.Forms.ToolStripMenuItem? _traySoundItem;
    private DateTimeOffset _lastSoundTime = DateTimeOffset.MinValue;

    public ObservableCollection<ConnectionRow> Rows { get; } = new();
    public ObservableCollection<ProgramRow> Programs { get; } = new();
    public ObservableCollection<StartupRow> StartupItems { get; } = new();
    public ObservableCollection<RuleRow> RuleRows { get; } = new();
    public ObservableCollection<PublisherRow> Publishers { get; } = new();
    public ObservableCollection<DnsRow> DnsRows { get; } = new();
    public ObservableCollection<EventLine> Events { get; } = new();
    public ObservableCollection<BlockRow> Blocks { get; } = new();
    public ObservableCollection<TopTalkerViewModel> TopTalkers { get; } = new();
    public ObservableCollection<ConnectionHistoryViewModel> ConnectionHistory { get; } = new();

    public MainWindow()
    {
        _dnsSwitch = new SystemDnsSwitchManager(null, null, () => _sink.LocalEndPoint);
        InitializeComponent();
        DataContext = this;
        DnsAdaptersList.ItemsSource = DnsAdapters;
        _dnsSwitch.StateChanged += _ => Dispatcher.BeginInvoke(new Action(UpdateDnsSwitchUi));

        InitSystemTray();
        if (_isAdmin)
        {
            _etw.TryStart();
            _dnsEtw.TryStart();
        }

        _rowsView = CollectionViewSource.GetDefaultView(Rows);
        _rowsView.Filter = RowFilter;

        // Re-evaluate the filter when a row's state changes (e.g. ESTABLISHED -> TIME_WAIT while "hide noise" is on).
        if (_rowsView is ICollectionViewLiveShaping live && live.CanChangeLiveFiltering)
        {
            live.LiveFilteringProperties.Add(nameof(ConnectionRow.StateValue));
            live.IsLiveFiltering = true;
        }

        _programsView = CollectionViewSource.GetDefaultView(Programs);
        _programsView.Filter = ProgramFilter;

        _startupView = CollectionViewSource.GetDefaultView(StartupItems);
        _startupView.Filter = StartupFilter;

        _dns.Resolved += OnHostResolved;
        _signatures.Verified += OnSignatureVerified;

        _promptToast = new NetworkPromptToastWindow();
        _promptToast.AllowRequested += OnToastAllow;
        _promptToast.BlockRequested += OnToastBlock;
        _promptToast.TrustRequested += OnToastTrust;
        _promptToast.LaterRequested += OnToastLater;
        Closed += (_, _) =>
        {
            _promptToast?.Close();
            _trayIcon?.Dispose();
            _etw.Dispose();
            _dnsEtw.Dispose();
            _historyDb.Dispose();
            _engineClient?.Dispose();
            _signatures.Dispose();
            _sink.Dispose();
            _dnsSwitch.Dispose();
        };

        _timer.Tick += async (_, _) => await TickAsync();
        Loaded += async (_, _) =>
        {
            await TryConnectEngineAsync();
            await RecoverStrictStateAsync();
            await RecoverDnsSwitchStateAsync();
            LoadDnsSettingsIntoUi();
            if (_sink.Settings.AutoStart) await StartDnsAsync();
            await RefreshAdaptersListAsync();
            UpdateDnsSwitchUi();
        DnsCustomRulesButton.Content = $"🛡️ Custom Rules ({_sink.Settings.CustomBlock.Count} blocked, {_sink.Settings.CustomAllow.Count} allowed)";
            UpdateElevationUi();

            if (_appSettings.Settings.InitialOperatingMode == "AskMode")
            {
                AskMode.IsChecked = true;
            }
            else if (_appSettings.Settings.InitialOperatingMode == "WatchOnly")
            {
                AskMode.IsChecked = false;
            }

            if (_appSettings.Settings.CheckForUpdatesOnStartup)
            {
                _ = CheckUpdatesAsync(manual: false);
            }
            AlwaysOnTopCheck.IsChecked = _appSettings.Settings.AlwaysOnTop;
            Topmost = _appSettings.Settings.AlwaysOnTop;
            NotificationSoundCheck.IsChecked = _appSettings.Settings.NotificationSoundEnabled;
            DnsFallbackModeBox.IsChecked = _appSettings.Settings.DnsFallbackModeEnabled;

            await TickAsync();
            _timer.Start();
        };
    }

    private async Task TryConnectEngineAsync()
    {
        try
        {
            var client = new IpcClient(IpcConstants.PipeName);
            await client.ConnectAsync(TimeSpan.FromMilliseconds(250));
            _engineClient = client;
            _engineClient.EventReceived += OnEngineEventReceived;
            _engineClient.Disconnected += OnEngineDisconnected;
            StatusText.Text = "Connected to SpectraNetworkManager Engine service (LocalSystem).";
        }
        catch
        {
            _engineClient = null;
            StatusText.Text = "Running Standalone (Local Process) — Engine service not active.";
        }
    }

    private void OnEngineEventReceived(IpcMessage msg)
    {
        Dispatcher.BeginInvoke(() =>
        {
            switch (msg.Action)
            {
                case IpcConstants.Events.MonitorTick:
                    var tick = msg.DeserializePayload<MonitorTick>();
                    if (tick != null) Apply(tick);
                    break;
                case IpcConstants.Events.StrictModeChanged:
                    UpdateStrictUi();
                    break;
                case IpcConstants.Events.DnsQuery:
                    var entry = msg.DeserializePayload<DnsLogEntry>();
                    if (entry != null)
                    {
                        string caller = ResolveInitiator(entry.Domain, entry.Client, entry.Detail, entry.Outcome == DnsOutcome.Blocked);
                        var row = DnsRow.From(entry, caller);
                        RecordDomainResolution(entry.Domain, entry.Detail);
                        _isUpdatingDnsRows = true;
                        try
                        {
                            DnsRows.Insert(0, row);
                            while (DnsRows.Count > 1000) DnsRows.RemoveAt(DnsRows.Count - 1);
                        }
                        finally
                        {
                            _isUpdatingDnsRows = false;
                        }
                    }
                    break;
                case IpcConstants.Events.BandwidthUpdate:
                    var samples = msg.DeserializePayload<List<ProcessBandwidthSample>>();
                    if (samples != null) UpdateBandwidthDisplay(samples);
                    break;
            }
        });
    }

    private void OnEngineDisconnected()
    {
        Dispatcher.BeginInvoke(() =>
        {
            _engineClient = null;
            StatusText.Text = "Engine service disconnected. Switched to standalone monitoring.";
        });
    }

    // ---- polling ---------------------------------------------------------------------------

    private async Task TickAsync()
    {
        if (_busy) return;
        _busy = true;
        try
        {
            var tick = await Task.Run(_monitor.Poll);
            Apply(tick);

            if (_engineClient == null && _etw.IsRunning)
            {
                var bwSamples = _etw.HarvestInterval(1.0);
                if (bwSamples.Count > 0)
                {
                    var now = DateTimeOffset.UtcNow;
                    foreach (var sample in bwSamples.Values)
                    {
                        var proc = tick.Connections.FirstOrDefault(c => c.Connection.ProcessId == sample.Pid)?.Process;
                        if (proc?.Path != null)
                        {
                            _historyDb.RecordBandwidth(now, proc.Path, sample.BytesReceivedPerSec, sample.BytesSentPerSec);
                        }
                    }
                    UpdateBandwidthDisplay(bwSamples.Values.ToList());
                }
            }

            _tickCount++;
            if (StrictActive && _isAdmin && _tickCount % 2 == 0) _ = PollBlockedAsync();
            RefreshDnsUi();
            UpdateLiveBandwidth();
        }
        catch (Exception ex)
        {
            StatusText.Text = "Monitor error: " + ex.Message;
        }
        finally
        {
            _busy = false;
        }
    }

    private void Apply(MonitorTick tick)
    {
        if (_engineClient == null)
        {
            var now = DateTimeOffset.UtcNow;
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
        }

        foreach (var conn in tick.Connections)
        {
            if (conn.Process != null && conn.Connection.Remote?.Address != null && conn.Process.Pid > 4 && !conn.Process.Name.StartsWith("(none", StringComparison.OrdinalIgnoreCase))
            {
                string rIp = conn.Connection.Remote.Address.ToString();
                RecordProcessSocket(rIp, conn.Process.Name, conn.Process.Pid);
                if (_resolvedDomainByIp.TryGetValue(rIp, out var dom))
                {
                    RecordProcessSocket(dom, conn.Process.Name, conn.Process.Pid);

                    string programWithPid = $"{conn.Process.Name} (PID {conn.Process.Pid})";
                    for (int i = 0; i < Math.Min(50, DnsRows.Count); i++)
                    {
                        var r = DnsRows[i];
                        if ((r.Domain.Equals(dom, StringComparison.OrdinalIgnoreCase) ||
                             (!string.IsNullOrEmpty(r.Detail) && r.Detail.Contains(rIp, StringComparison.OrdinalIgnoreCase))) &&
                            (string.IsNullOrEmpty(r.CallerProgram) || r.CallerProgram.StartsWith("svchost", StringComparison.OrdinalIgnoreCase)))
                        {
                            r.CallerProgram = programWithPid;
                            if (ReferenceEquals(r, _inspectedDnsRow) && DnsInspectorPanel.Visibility == Visibility.Visible)
                            {
                                InspectorInitiator.Text = programWithPid;
                            }
                        }
                    }
                }
            }
        }

        foreach (var closed in tick.Closed)
        {
            var key = ConnectionKey.From(closed.Connection);
            if (_rows.Remove(key, out var gone)) Rows.Remove(gone);
            if (!IsNoise(closed)) AddEvent(tick.Time, "-", closed, opened: false);
        }

        var activeKeys = new HashSet<ConnectionKey>(tick.Connections.Count);
        var alivePids = new HashSet<int>();
        bool resolve = ResolveHosts.IsChecked == true;
        foreach (var view in tick.Connections)
        {
            if (view.Connection.ProcessId > 0) alivePids.Add(view.Connection.ProcessId);
            var key = ConnectionKey.From(view.Connection);
            activeKeys.Add(key);
            if (_rows.TryGetValue(key, out var existing))
            {
                existing.StateValue = view.Connection.State;
                continue;
            }

            var row = new ConnectionRow(view);
            if (row.Path.Length > 0) row.SetSignature(_signatures.TryGet(row.Path));
            if (resolve && row.RemoteAddress is not null)
                row.Host = _dns.Request(row.RemoteAddress) ?? "";
            if (row.Host.Length == 0 && row.RemoteAddress is not null && _resolvedDomainByIp.TryGetValue(row.RemoteAddress.ToString(), out var knownDom))
                row.Host = knownDom;
            _rows[key] = row;
            Rows.Add(row);
        }

        // Reconcile any stale connection rows whose closed diff was missed
        if (_rows.Count > activeKeys.Count)
        {
            foreach (var staleKey in _rows.Keys.Where(k => !activeKeys.Contains(k)).ToList())
            {
                if (_rows.Remove(staleKey, out var gone))
                {
                    Rows.Remove(gone);
                }
            }
        }

        // Periodically prune terminated PIDs from DNS caller caches so dead processes never linger as ghost callers
        if (_tickCount % 5 == 0)
        {
            _dnsEtw.Prune(alivePids);
            var staleCutoff = DateTimeOffset.UtcNow.AddSeconds(-45);
            foreach (var kv in _recentProcessByHostOrIp.ToList())
            {
                if (!alivePids.Contains(kv.Value.Pid) && kv.Value.LastSeen < staleCutoff)
                {
                    _recentProcessByHostOrIp.TryRemove(kv.Key, out _);
                }
            }
        }

        foreach (var opened in tick.Opened)
            if (!IsNoise(opened)) AddEvent(tick.Time, "+", opened, opened: true);

        _lastConnections = tick.Connections;
        var summaries = ProgramAggregator.Summarize(_lastConnections);
        UpdateProgramRows(summaries);
        RunLearning(tick.Time, summaries);
        UpdateStatus();
    }

    // When a TCP connection enters TIME_WAIT, Windows reassigns it to PID 0, which would show up as a fake close + open.
    private static bool IsNoise(ConnectionView v) =>
        v.Connection.ProcessId == 0 ||
        (v.Connection.Protocol == Protocol.Tcp && Display.IsTeardownNoise(v.Connection.State));

    private void AddEvent(DateTimeOffset time, string sign, ConnectionView v, bool opened)
    {
        var c = v.Connection;
        string target = c.Protocol == Protocol.Udp
            ? $"listening {Display.Endpoint(c.Local)}"
            : $"{Display.Endpoint(c.Local)} -> {Display.Endpoint(c.Remote)}";
        Events.Insert(0, new EventLine($"{sign} {time:HH:mm:ss} {c.Protocol.ToString().ToUpperInvariant()} {v.Process.Name}  {target}", opened));
        TrimEvents();
    }

    private void AddAlert(DateTimeOffset time, string text)
    {
        Events.Insert(0, new EventLine($"! {time:HH:mm:ss} {text}", Opened: false, Alert: true));
        TrimEvents();
    }

    private void TrimEvents()
    {
        while (Events.Count > MaxEventLines) Events.RemoveAt(Events.Count - 1);
    }

    private void UpdateStatus()
    {
        int established = Rows.Count(r => r.StateValue == ConnectionState.Established);
        int listening = Rows.Count(r => r.StateValue == ConnectionState.Listen);
        int processes = Rows.Select(r => r.Pid).Distinct().Count();
        int undecided = Programs.Count(p => p.IsNew);
        string strict = StrictActive ? "STRICT MODE ON  |  " : "";
        StatusText.Text = $"{strict}{Rows.Count} entries  |  {established} established  |  {listening} listening  |  {processes} processes  |  {undecided} programs without a decision";
    }

    // ---- programs view ---------------------------------------------------------------------

    private void UpdateProgramRows(IReadOnlyList<ProgramSummary> summaries)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var s in summaries)
        {
            seen.Add(s.Key);
            var standing = StandingOf(s.Path);
            if (_programRows.TryGetValue(s.Key, out var row))
            {
                row.Update(s, standing);
            }
            else
            {
                row = new ProgramRow(s, standing);
                _programRows[s.Key] = row;
                Programs.Add(row);
            }
        }

        foreach (var key in _programRows.Keys.Where(k => !seen.Contains(k)).ToList())
        {
            Programs.Remove(_programRows[key]);
            _programRows.Remove(key);
        }
    }

    private void RefreshProgramRows() => UpdateProgramRows(ProgramAggregator.Summarize(_lastConnections));

    // ---- standing: your decision + verified signature + trusted publishers ------------------

    private ProgramStanding StandingOf(string? path)
    {
        var rule = _rules.Find(path);
        var signature = string.IsNullOrEmpty(path) ? null : _signatures.TryGet(path);
        bool publisherTrusted = signature?.Publisher is string publisher && _rules.IsTrustedPublisher(publisher);
        return new ProgramStanding(rule, signature, publisherTrusted);
    }

    private void OnSignatureVerified(string path, SignatureInfo info)
    {
        // Called on a background thread; everything below touches UI-owned data.
        Dispatcher.BeginInvoke(new Action(() =>
        {
            foreach (var row in Rows)
                if (row.Path.Equals(path, StringComparison.OrdinalIgnoreCase))
                    row.SetSignature(info);

            foreach (var sRow in StartupItems)
                if (sRow.ExecutablePath.Equals(path, StringComparison.OrdinalIgnoreCase))
                    sRow.Update(sRow.Entry, info, DescribeStartupFirewall(sRow.ExecutablePath));

            if (info.IsAlarming && _alarmed.Add(path) && Programs.Any(p => p.Path.Equals(path, StringComparison.OrdinalIgnoreCase)))
                AddAlert(DateTimeOffset.Now, $"WARNING: {System.IO.Path.GetFileName(path)} - {info.Describe()}");

            if (_awaiting.Remove(path, out var waiting))
                AnnounceNew(DateTimeOffset.Now, waiting.Summary, StandingOf(path));

            if (_strictAwaiting.Remove(path))
                DecideBlocked(path, StandingOf(path));

            RefreshProgramRows();
        }));
    }

    // ---- learning + ask mode ---------------------------------------------------------------

    private void RunLearning(DateTimeOffset time, IReadOnlyList<ProgramSummary> summaries)
    {
        var update = _learning.Update(summaries, path => StandingOf(path).IsDecided);

        if (update.BaselineCount is int baseline && baseline > 0)
            AddAlert(time, $"{baseline} programs were already online when SpectraNetworkManager started (see Programs view)");

        foreach (var s in update.NewPrograms)
            HandleNewProgram(time, s);

        // A signature check that takes too long must not hold back the question forever.
        foreach (var (path, waiting) in _awaiting.Where(kv => time - kv.Value.Since > TimeSpan.FromSeconds(20)).ToList())
        {
            _awaiting.Remove(path);
            AnnounceNew(time, waiting.Summary, StandingOf(path));
        }
    }

    private void HandleNewProgram(DateTimeOffset time, ProgramSummary s)
    {
        var standing = StandingOf(s.Path);

        // Wait for the signature result first: a program from a publisher you trust should never bother you.
        if (standing.Signature is null && s.Path is not null)
        {
            _awaiting[s.Path] = (s, time);
            return;
        }

        AnnounceNew(time, s, standing);
    }

    private void AnnounceNew(DateTimeOffset time, ProgramSummary s, ProgramStanding standing)
    {
        if (standing.IsDecided) return;

        AddAlert(time, standing.Signature is { IsAlarming: true } bad
            ? $"WARNING: {s.Name} has internet access and a bad signature ({bad.Describe()})"
            : $"NEW program with internet access and no decision: {s.Name}");

        // Windows' own programs are listed but never asked about: you could not block them from here anyway.
        if (AskMode.IsChecked == true && !ProtectedPrograms.IsProtected(s.Path, standing.Signature, out _))
            EnqueueAsk(s);
    }

    private void EnqueueAsk(ProgramSummary s)
    {
        if (!_askQueued.Add(s.Path!)) return;
        _askQueue.Enqueue(s);
        ShowNextAsk();

        // We cannot pause the program's first connection (that needs a kernel driver), so the question comes right after it.
        if (!IsActive) NativeMethods.FlashUntilActivated(new WindowInteropHelper(this).Handle);
    }

    private void ShowNextAsk()
    {
        if (_askCurrent is not null && StandingOf(_askCurrent.Path).IsDecided)
            _askCurrent = null;                                     // already decided somewhere else

        while (_askCurrent is null && _askQueue.TryDequeue(out var next))
            if (!StandingOf(next.Path).IsDecided) _askCurrent = next;

        if (_askCurrent is null)
        {
            DecisionBar.Visibility = Visibility.Collapsed;
            _promptToast?.Hide();
            return;
        }

        var s = _askCurrent;
        var standing = StandingOf(s.Path);
        string more = _askQueue.Count > 0 ? $"   (+{_askQueue.Count} more waiting)" : "";
        string warning = standing.Signature is { IsAlarming: true } ? "   - WARNING: its signature is not valid!" : "";

        string verb = s.Path is not null && _blockedDest.ContainsKey(s.Path) ? "was blocked by strict mode" : "wants to use the network";
        AskTitle.Text = $"{s.Name} {verb}{warning}{more}";
        AskDetail.Text =
            $"{s.Path}\n" +
            $"Signer: {standing.Signature?.Describe() ?? "checking..."}\n" +
            $"Talking to: {DescribePeers(s)}";

        bool canTrust = standing.Signature is { Status: SignatureStatus.Valid, Publisher: not null } && !standing.PublisherTrusted;
        AskTrustButton.Content = canTrust ? $"Trust {standing.Signature!.Publisher}" : "Trust publisher";
        AskTrustButton.Visibility = canTrust ? Visibility.Visible : Visibility.Collapsed;
        DecisionBar.Visibility = Visibility.Visible;
        if (_appSettings.Settings.InteractiveToastsEnabled)
        {
            _promptToast?.DisplayPrompt(s, standing, DescribePeers(s), _askQueue.Count);
        }
        else if (Visibility != Visibility.Visible || WindowState == WindowState.Minimized || !IsActive)
        {
            _trayIcon?.ShowBalloonTip(4000, "SpectraNetworkManager: Network Prompt", $"{s.Name} wants to reach the network. Click to review.", System.Windows.Forms.ToolTipIcon.Warning);
        }

        PlayPromptSoundIfEnabled();
    }

    private string DescribePeers(ProgramSummary s)
    {
        bool lookup = ResolveHosts.IsChecked == true;
        var peers = _lastConnections
            .Where(v => string.Equals(v.Process.Path ?? v.Process.Name, s.Key, StringComparison.OrdinalIgnoreCase))
            .Where(v => v.Connection.Protocol == Protocol.Tcp
                     && v.Connection.State is ConnectionState.Established or ConnectionState.SynSent
                     && v.Connection.Remote is not null
                     && !Display.IsLocalAddress(v.Connection.Remote.Address))
            .Select(v =>
            {
                var remote = v.Connection.Remote!;
                string? host = lookup ? _dns.Request(remote.Address) : null;
                return host is null ? Display.Endpoint(remote) : $"{host}:{remote.Port}";
            })
            .Distinct()
            .Take(3)
            .ToList();

        if (peers.Count > 0) return string.Join(",  ", peers);
        return s.Path is not null && _blockedDest.TryGetValue(s.Path, out var blocked)
            ? $"{blocked} (blocked)"
            : "(no internet connection right now)";
    }

    private void OnAskModeChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || AskMode.IsChecked == true) return;
        _askQueue.Clear();
        _askCurrent = null;
        _promptToast?.Hide();
        ShowNextAsk();
    }

    private void OnAskAllow(object sender, RoutedEventArgs e)
    {
        if (_askCurrent?.Path is not string path) return;
        if (!TryAllow(path, _askCurrent.Name, existing: null)) return;
        _askCurrent = null;
        AfterDecision();
    }

    private void OnAskBlock(object sender, RoutedEventArgs e)
    {
        if (_askCurrent?.Path is not string path) return;
        if (!TryBlock(path, _askCurrent.Name)) return;
        _askCurrent = null;
        AfterDecision();
    }

    private void OnAskLater(object sender, RoutedEventArgs e)
    {
        _askCurrent = null;
        ShowNextAsk();
    }

    private void OnAskTrust(object sender, RoutedEventArgs e)
    {
        if (_askCurrent?.Path is not string path) return;
        if (!TryTrustPublisher(StandingOf(path).Signature)) return;
        _askCurrent = null;
        AfterDecision();
    }

    private void OnToastAllow(ProgramSummary s)
    {
        if (s.Path is not string path) return;
        TryAllow(path, s.Name, existing: null);
        if (_askCurrent?.Path == path)
        {
            _askCurrent = null;
        }
        AfterDecision();
    }

    private void OnToastBlock(ProgramSummary s)
    {
        if (s.Path is not string path) return;
        TryQuickBlock(path, s.Name);
        if (_askCurrent?.Path == path)
        {
            _askCurrent = null;
        }
        AfterDecision();
    }

    private void OnToastTrust(ProgramSummary s)
    {
        if (s.Path is not string path) return;
        TryTrustPublisher(StandingOf(path).Signature);
        if (_askCurrent?.Path == path)
        {
            _askCurrent = null;
        }
        AfterDecision();
    }

    private void OnToastLater(ProgramSummary s)
    {
        _askCurrent = null;
        ShowNextAsk();
    }

    private bool TryQuickBlock(string path, string name)
    {
        if (ProtectedPrograms.IsProtected(path, _signatures.TryGet(path), out string why))
        {
            Info(why);
            return false;
        }

        if (!_isAdmin)
        {
            Info("Blocking changes Windows Firewall, which requires Administrator rights.\n\nRestart SpectraNetworkManager as Administrator to apply block rules.");
            return false;
        }

        try
        {
            var plan = RulePlanner.Plan(RuleDirection.Both, TrafficScope.All);
            _enforcer.Block(path, plan);
            _ = TerminateConnectionsAsync(path);
            _rules.Set(new ProgramRule(path, RuleAction.Block, DateTimeOffset.Now, null, RuleDirection.Both, null));
            StatusText.Text = $"Blocked {name}: all traffic.";
            return true;
        }
        catch (Exception ex)
        {
            Error("Could not add the firewall rules", ex);
            return false;
        }
    }

    private void OnAlwaysOnTopChanged(object sender, RoutedEventArgs e)
    {
        bool enable = AlwaysOnTopCheck.IsChecked == true;
        Topmost = enable;
        if (enable == _appSettings.Settings.AlwaysOnTop) return;
        _appSettings.Save(_appSettings.Settings with { AlwaysOnTop = enable });
        if (_trayAlwaysOnTopItem != null && _trayAlwaysOnTopItem.Checked != enable)
        {
            _trayAlwaysOnTopItem.Checked = enable;
        }
    }

    private void OnNotificationSoundChanged(object sender, RoutedEventArgs e)
    {
        bool enable = NotificationSoundCheck.IsChecked == true;
        if (enable == _appSettings.Settings.NotificationSoundEnabled) return;
        _appSettings.Save(_appSettings.Settings with { NotificationSoundEnabled = enable });
        if (_traySoundItem != null && _traySoundItem.Checked != enable)
        {
            _traySoundItem.Checked = enable;
        }
    }

    private void OnFallbackModeChanged(object sender, RoutedEventArgs e)
    {
        bool enable = DnsFallbackModeBox.IsChecked == true;
        if (enable == _appSettings.Settings.DnsFallbackModeEnabled) return;
        _appSettings.Save(_appSettings.Settings with { DnsFallbackModeEnabled = enable });
    }

    private void PlayPromptSoundIfEnabled()
    {
        if (!_appSettings.Settings.NotificationSoundEnabled) return;

        var now = DateTimeOffset.Now;
        if ((now - _lastSoundTime).TotalSeconds < 3.0) return;
        _lastSoundTime = now;

        try
        {
            System.Media.SystemSounds.Asterisk.Play();
        }
        catch { /* best effort */ }
    }

    // ---- decisions: allow / block / forget / panic -----------------------------------------
    // Each Try... method returns true only if it really changed something, and shows its own error message otherwise.

    private bool TryAllow(string path, string name, ProgramRule? existing)
    {
        if (string.IsNullOrEmpty(path))
        {
            Info("This program's file path is unknown. Run SpectraNetworkManager as Administrator so Windows reveals it.");
            return false;
        }

        try
        {
            if (existing?.Action == RuleAction.Block) _enforcer.Unblock(path);
            if (StrictActive) _enforcer.Allow(new AllowSpec(name, path, null));   // in strict mode "Allow" must really open the way
            _rules.Set(new ProgramRule(path, RuleAction.Allow, DateTimeOffset.Now));
            _allowEnsured.Add(path);
            StatusText.Text = $"Allowed {name}.";
            return true;
        }
        catch (Exception ex)
        {
            Error("Could not remove the existing block", ex);
            return false;
        }
    }

    private bool TryBlock(string path, string name, ProgramRule? existing = null)
    {
        if (ProtectedPrograms.IsProtected(path, _signatures.TryGet(path), out string why))
        {
            Info(why);
            return false;
        }

        if (!_isAdmin)
        {
            Info("Blocking changes Windows Firewall, which needs Administrator rights.\n\nClose SpectraNetworkManager and start it again with 'Run as administrator'.");
            return false;
        }

        var dialog = new BlockDialog(this, name, path, existing);
        if (dialog.ShowDialog() != true) return false;

        try
        {
            var plan = RulePlanner.Plan(dialog.Direction, dialog.Scope);
            _enforcer.Block(path, plan);

            // Automatically sever any existing active TCP connections for this program immediately
            _ = TerminateConnectionsAsync(path);

            var scope = dialog.Scope.IsEverything ? null : dialog.Scope;
            _rules.Set(new ProgramRule(path, RuleAction.Block, DateTimeOffset.Now, null, dialog.Direction, scope));
            StatusText.Text = $"Blocked {name}: {dialog.Scope.Describe()}, {ProgramRule.DescribeDirection(dialog.Direction)} ({plan.Count} firewall rules, group \"{WindowsFirewallEnforcer.Group}\").";
            return true;
        }
        catch (Exception ex)
        {
            Error("Could not add the firewall rules", ex);
            return false;
        }
    }

    private bool TryForget(ProgramRule rule, string name)
    {
        try
        {
            if (rule.Action == RuleAction.Block) _enforcer.Unblock(rule.Path);
            else if (StrictActive) _enforcer.RemoveAllow(rule.Path);
            _rules.Remove(rule.Path);
            _allowEnsured.Remove(rule.Path);
            _strictSeen.Remove(rule.Path);
            StatusText.Text = $"Forgot the decision for {name}.";
            return true;
        }
        catch (Exception ex)
        {
            Error("Could not remove the block", ex);
            return false;
        }
    }

    private bool TryTrustPublisher(SignatureInfo? signature)
    {
        if (signature is not { Status: SignatureStatus.Valid, Publisher: string publisher })
        {
            Info("This program has no verified signature, so there is no publisher to trust.");
            return false;
        }

        var answer = MessageBox.Show(this,
            $"Trust everything with a verified signature from \"{publisher}\"?\n\n" +
            "Programs signed by this publisher will no longer be asked about and are shown as Trusted. " +
            "Your own Block decisions still win, and you can remove the trust in the Rules view.",
            "Trust publisher", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return false;

        _rules.TrustPublisher(publisher);

        if (StrictActive)
        {
            foreach (var row in Programs.Where(p => p.Path.Length > 0 && p.Signature is { Status: SignatureStatus.Valid } sig
                                                     && string.Equals(sig.Publisher, publisher, StringComparison.OrdinalIgnoreCase)).ToList())
            {
                try { _enforcer.Allow(new AllowSpec(row.Name, row.Path, null)); _allowEnsured.Add(row.Path); }
                catch (Exception) { /* it will be asked about again if it is blocked */ }
            }
        }

        StatusText.Text = $"Now trusting verified programs from {publisher}.";
        return true;
    }

    private void AfterDecision()
    {
        RefreshProgramRows();
        ShowNextAsk();
        _ = RefreshRulesAsync();
    }

    // -- Programs view buttons --

    private ProgramRow? SelectedProgram()
    {
        if (ProgramsGrid.SelectedItem is ProgramRow row) return row;
        Info("Select a program in the list first.");
        return null;
    }

    private void OnAllowProgram(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is not null && TryAllow(row.Path, row.Name, row.Rule)) AfterDecision();
    }

    private void OnBlockProgram(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is not null && TryBlock(row.Path, row.Name)) AfterDecision();
    }

    private void OnForgetProgram(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is null) return;
        if (row.Rule is null)
        {
            Info("There is no decision for this program yet.");
            return;
        }
        if (TryForget(row.Rule, row.Name)) AfterDecision();
    }

    private void OnTrustPublisher(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is not null && TryTrustPublisher(row.Signature)) AfterDecision();
    }

    // -- Connection & Process termination helpers --

    private async Task<int> TerminateConnectionsAsync(string? programPath, int? pid = null, IPEndPoint? local = null, IPEndPoint? remote = null)
    {
        // Try via IPC Engine service first if connected
        if (_engineClient?.IsConnected == true)
        {
            try
            {
                var resp = await _engineClient.SendRequestAsync<TerminateConnectionsResult>(
                    IpcConstants.Actions.TerminateConnections,
                    new TerminateConnectionsRequest(
                        Pid: pid,
                        ProgramPath: programPath,
                        LocalEndPoint: local?.ToString(),
                        RemoteEndPoint: remote?.ToString()));
                if (resp is not null) return resp.Closed;
            }
            catch { }
        }

        // Direct fallback on Windows
        if (OperatingSystem.IsWindows())
        {
            var terminator = new TcpConnectionTerminator();
            if (pid.HasValue && pid.Value > 0)
                return terminator.TerminateConnectionsForPid(pid.Value);
            if (!string.IsNullOrWhiteSpace(programPath))
                return terminator.TerminateConnectionsForProgram(programPath);
            if (local is not null && remote is not null)
                return terminator.TerminateConnection(local, remote) ? 1 : 0;
        }

        return 0;
    }

    private async Task<bool> TerminateProcessAsync(int pid)
    {
        if (pid <= 0) return false;

        if (_engineClient?.IsConnected == true)
        {
            try
            {
                var resp = await _engineClient.SendRequestAsync<TerminateProcessResult>(
                    IpcConstants.Actions.TerminateProcess,
                    new TerminateProcessRequest(pid));
                if (resp is not null) return resp.Killed;
            }
            catch { }
        }

        if (OperatingSystem.IsWindows())
        {
            return TcpConnectionTerminator.KillProcess(pid);
        }

        return false;
    }

    private void PurgeTerminatedProcess(int pid)
    {
        if (pid <= 0) return;
        _processResolver.Remove(pid);
        _dnsEtw.PurgePid(pid);
        foreach (var kv in _recentProcessByHostOrIp.Where(kv => kv.Value.Pid == pid).ToList())
        {
            _recentProcessByHostOrIp.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _rows.Where(kv => kv.Value.Pid == pid).ToList())
        {
            if (_rows.Remove(kv.Key, out var gone))
            {
                Rows.Remove(gone);
            }
        }
    }

    private async Task ForceMonitorRefreshAsync()
    {
        try
        {
            var tick = await Task.Run(_monitor.Poll);
            Apply(tick);
        }
        catch { }
    }

    private async void OnCloseProgramConnections(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is null) return;

        int closed = await TerminateConnectionsAsync(row.Path);
        if (closed > 0)
        {
            StatusText.Text = $"Terminated {closed} active TCP connection(s) for {row.Name}.";
        }
        else
        {
            StatusText.Text = $"No active IPv4 TCP connections found to close for {row.Name}.";
        }
        await ForceMonitorRefreshAsync();
        RefreshProgramRows();
    }

    private async void OnKillProgramProcess(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is null) return;

        var answer = MessageBox.Show(this,
            $"Terminate all running processes for \"{row.Name}\"?\n\nPath: {row.Path}\n\nUnsaved work in this application will be lost.",
            "End Process", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        int killed = 0;
        if (!string.IsNullOrWhiteSpace(row.Path))
        {
            try
            {
                var running = System.Diagnostics.Process.GetProcesses()
                    .Where(p =>
                    {
                        try { return string.Equals(p.MainModule?.FileName, row.Path, StringComparison.OrdinalIgnoreCase); }
                        catch { return string.Equals(p.ProcessName + ".exe", row.Name, StringComparison.OrdinalIgnoreCase); }
                    })
                    .ToList();

                foreach (var p in running)
                {
                    if (await TerminateProcessAsync(p.Id))
                    {
                        killed++;
                        PurgeTerminatedProcess(p.Id);
                    }
                }
            }
            catch { }
        }

        StatusText.Text = killed > 0
            ? $"Terminated {killed} process instance(s) of {row.Name}."
            : $"Could not terminate process for {row.Name}. It may already have exited or requires Administrator rights.";
        await ForceMonitorRefreshAsync();
        RefreshProgramRows();
    }

    private void OnOpenProgramLocation(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is null || string.IsNullOrWhiteSpace(row.Path)) return;
        try
        {
            if (File.Exists(row.Path))
            {
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{row.Path}\"");
            }
            else
            {
                Info($"The file was not found on disk:\n\n{row.Path}");
            }
        }
        catch (Exception ex)
        {
            Error("Could not open file location", ex);
        }
    }

    private void OnCopyProgramPath(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is null || string.IsNullOrWhiteSpace(row.Path)) return;
        try
        {
            System.Windows.Clipboard.SetText(row.Path);
            StatusText.Text = $"Copied path to clipboard: {row.Path}";
        }
        catch { }
    }

    // -- Connection view context menu actions --

    private ConnectionRow? SelectedConnection()
    {
        if (ConnectionsGrid.SelectedItem is ConnectionRow row) return row;
        Info("Select a connection in the list first.");
        return null;
    }

    private async void OnCloseSelectedConnection(object sender, RoutedEventArgs e)
    {
        var row = SelectedConnection();
        if (row is null) return;

        if (IPEndPoint.TryParse(row.Local, out var local) && IPEndPoint.TryParse(row.Remote, out var remote))
        {
            int closed = await TerminateConnectionsAsync(null, pid: row.Pid, local: local, remote: remote);
            StatusText.Text = closed > 0
                ? $"Terminated TCP connection {row.Local} -> {row.Remote} ({row.Program})."
                : $"Could not close connection {row.Local} -> {row.Remote} (connection may already be closed, or is IPv6/UDP).";
        }
        else
        {
            int closed = await TerminateConnectionsAsync(null, pid: row.Pid);
            StatusText.Text = closed > 0
                ? $"Terminated {closed} TCP connection(s) for PID {row.Pid} ({row.Program})."
                : $"No active IPv4 TCP connections closed for PID {row.Pid}.";
        }
        await ForceMonitorRefreshAsync();
    }

    private async void OnCloseConnectionProgram(object sender, RoutedEventArgs e)
    {
        var row = SelectedConnection();
        if (row is null) return;

        int closed = await TerminateConnectionsAsync(row.Path, pid: row.Pid);
        StatusText.Text = closed > 0
            ? $"Terminated {closed} active TCP connection(s) for {row.Program}."
            : $"No active IPv4 TCP connections found to close for {row.Program}.";
        await ForceMonitorRefreshAsync();
    }

    private async void OnKillConnectionProcess(object sender, RoutedEventArgs e)
    {
        var row = SelectedConnection();
        if (row is null) return;

        var answer = MessageBox.Show(this,
            $"Terminate process \"{row.Program}\" (PID {row.Pid})?\n\nPath: {row.Path}\n\nUnsaved work in this application will be lost.",
            "End Process", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        bool ok = await TerminateProcessAsync(row.Pid);
        if (ok) PurgeTerminatedProcess(row.Pid);
        StatusText.Text = ok
            ? $"Terminated process {row.Program} (PID {row.Pid})."
            : $"Could not terminate PID {row.Pid} (it may have exited or requires Administrator rights).";
        await ForceMonitorRefreshAsync();
    }

    private async void OnStopConnectionService(object sender, RoutedEventArgs e)
    {
        var row = SelectedConnection();
        if (row is null) return;
        await PromptAndStopServiceAsync(row.Pid, row.Program, row.Path);
    }

    private async void OnStopProgramService(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is null) return;
        int pid = Rows.FirstOrDefault(c => !string.IsNullOrEmpty(row.Path) && string.Equals(c.Path, row.Path, StringComparison.OrdinalIgnoreCase))?.Pid
                  ?? Rows.FirstOrDefault(c => string.Equals(c.Program, row.Name, StringComparison.OrdinalIgnoreCase))?.Pid
                  ?? 0;
        await PromptAndStopServiceAsync(pid, row.Name, row.Path);
    }

    private async Task PromptAndStopServiceAsync(int pid, string programName, string path)
    {
        var services = WindowsServiceManager.GetServicesForProcess(pid, programName);
        if (services.Count == 0)
        {
            MessageBox.Show(this,
                $"Process \"{programName}\" (PID {pid}) does not appear to be running as a registered Windows Service.\n\n" +
                "To terminate standard application processes, use 'End Process (Kill)' or 'Close connections'.",
                "Not a Windows Service", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string serviceList = string.Join("\n", services.Select(s => $"• {s.DisplayName} ({s.ServiceName}) - {s.StateDescription}"));
        var answer = MessageBox.Show(this,
            $"Stop the following Windows Service(s) for \"{programName}\"?\n\n{serviceList}\n\n" +
            (services.Count > 1 ? "Stopping this process will stop all services hosted in it." : ""),
            "Stop Windows Service", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        foreach (var svc in services)
        {
            var res = await WindowsServiceManager.StopServiceAsync(svc.ServiceName);
            StatusText.Text = res.Message;
        }

        PurgeTerminatedProcess(pid);
        await ForceMonitorRefreshAsync();
    }

    private void OnBlockConnectionProgram(object sender, RoutedEventArgs e)
    {
        var row = SelectedConnection();
        if (row is not null && !string.IsNullOrWhiteSpace(row.Path) && TryBlock(row.Path, row.Program)) AfterDecision();
    }

    private void OnAllowConnectionProgram(object sender, RoutedEventArgs e)
    {
        var row = SelectedConnection();
        if (row is not null && !string.IsNullOrWhiteSpace(row.Path) && TryAllow(row.Path, row.Program, null)) AfterDecision();
    }

    private void OnCopyConnectionRemote(object sender, RoutedEventArgs e)
    {
        var row = SelectedConnection();
        if (row is null) return;
        string text = !string.IsNullOrWhiteSpace(row.Host) ? $"{row.Remote} ({row.Host})" : row.Remote;
        try
        {
            System.Windows.Clipboard.SetText(text);
            StatusText.Text = $"Copied remote address to clipboard: {text}";
        }
        catch { }
    }

    private void OnOpenConnectionLocation(object sender, RoutedEventArgs e)
    {
        var row = SelectedConnection();
        if (row is null || string.IsNullOrWhiteSpace(row.Path)) return;
        try
        {
            if (File.Exists(row.Path))
            {
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{row.Path}\"");
            }
            else
            {
                Info($"The file was not found on disk:\n\n{row.Path}");
            }
        }
        catch (Exception ex)
        {
            Error("Could not open file location", ex);
        }
    }

    // -- Rules view buttons --

    private RuleRow? SelectedRule()
    {
        if (RulesGrid.SelectedItem is RuleRow row) return row;
        Info("Select a decision in the list first.");
        return null;
    }

    private async void OnRefreshRules(object sender, RoutedEventArgs e) => await RefreshRulesAsync();

    private void OnUntrustPublisher(object sender, RoutedEventArgs e)
    {
        if (PublishersGrid.SelectedItem is not PublisherRow row)
        {
            Info("Select a publisher in the list first.");
            return;
        }

        _rules.UntrustPublisher(row.Name);
        StatusText.Text = $"No longer trusting {row.Name}.";
        AfterDecision();
    }

    private void OnRulesAllow(object sender, RoutedEventArgs e)
    {
        var row = SelectedRule();
        if (row is not null && TryAllow(row.Rule.Path, row.Name, row.Rule)) AfterDecision();
    }

    private void OnRulesEdit(object sender, RoutedEventArgs e)
    {
        var row = SelectedRule();
        if (row is not null && TryBlock(row.Rule.Path, row.Name, row.Rule)) AfterDecision();
    }

    private void OnRulesForget(object sender, RoutedEventArgs e)
    {
        var row = SelectedRule();
        if (row is not null && TryForget(row.Rule, row.Name)) AfterDecision();
    }

    private async Task RefreshRulesAsync()
    {
        IReadOnlyDictionary<string, int>? counts = null;
        try
        {
            counts = await Task.Run(() => _enforcer.CountByProgram());
        }
        catch (Exception)
        {
            // Could not read the firewall: show "unknown" instead of guessing.
        }

        RuleRows.Clear();
        foreach (var rule in _rules.All.OrderBy(r => r.Path, StringComparer.OrdinalIgnoreCase))
            RuleRows.Add(RuleRow.From(rule, FirewallStatus(rule, counts)));

        Publishers.Clear();
        foreach (var name in _rules.TrustedPublishers.OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
            Publishers.Add(new PublisherRow(name));

        int missingCount = RuleRows.Count(r => r.Decision == "Blocked" && (r.Firewall == "MISSING" || r.Firewall.StartsWith("PARTIAL", StringComparison.OrdinalIgnoreCase)));
        if (missingCount > 0)
        {
            MissingRulesBannerText.Text = $"Attention: {missingCount} block rule(s) are missing from Windows Firewall and currently inactive!";
            FixRulesButton.Content = $"⚡ Fix {missingCount} Rule{(missingCount > 1 ? "s" : "")}";
            MissingRulesBanner.Visibility = Visibility.Visible;
        }
        else
        {
            MissingRulesBanner.Visibility = Visibility.Collapsed;
        }
    }

    // Compares the number of firewall rules we expect for a block with the number that really exist.
    private static string FirewallStatus(ProgramRule rule, IReadOnlyDictionary<string, int>? counts)
    {
        if (rule.Action != RuleAction.Block) return "-";
        if (counts is null) return "unknown";

        int expected;
        try { expected = RulePlanner.Plan(rule.Direction, rule.EffectiveScope).Count; }
        catch (ArgumentException) { return "invalid"; }

        int actual = counts.GetValueOrDefault(rule.Path);
        if (actual == 0) return "MISSING";
        if (actual < expected) return $"PARTIAL {actual}/{expected}";
        return actual == expected ? "active" : "active (+extra)";
    }

    private async void OnFixMissingRules(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin && _engineClient?.IsConnected != true)
        {
            Info("Reapplying firewall rules requires Administrator rights.\n\nRestart SpectraNetworkManager as Administrator to apply block rules.");
            return;
        }

        FixRulesButton.IsEnabled = false;
        StatusText.Text = "Reapplying missing firewall rules...";

        try
        {
            var missingRules = RuleRows
                .Where(r => r.Decision == "Blocked" && (r.Firewall == "MISSING" || r.Firewall.StartsWith("PARTIAL", StringComparison.OrdinalIgnoreCase)))
                .Select(r => r.Rule)
                .ToList();

            if (missingRules.Count == 0)
            {
                MissingRulesBanner.Visibility = Visibility.Collapsed;
                StatusText.Text = "All block rules are already active in Windows Firewall.";
                return;
            }

            int fixedCount = 0;
            if (_engineClient?.IsConnected == true)
            {
                foreach (var rule in missingRules)
                {
                    try
                    {
                        await _engineClient.SendRequestAsync(IpcConstants.Actions.AddRule, rule);
                        fixedCount++;
                    }
                    catch (Exception) { }
                }
            }
            else
            {
                await Task.Run(() =>
                {
                    foreach (var rule in missingRules)
                    {
                        try
                        {
                            var plan = RulePlanner.Plan(rule.Direction, rule.EffectiveScope);
                            _enforcer.Block(rule.Path, plan);
                            fixedCount++;
                        }
                        catch (Exception) { }
                    }
                });
            }

            await RefreshRulesAsync();
            StatusText.Text = $"Successfully reapplied {fixedCount} missing firewall rule(s). All block rules are now active.";
        }
        catch (Exception ex)
        {
            Error("Failed to reapply firewall rules", ex);
        }
        finally
        {
            FixRulesButton.IsEnabled = true;
        }
    }

    // -- panic --

    private async void OnPanic(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin && _engineClient?.IsConnected != true)
        {
            Info("Undoing firewall changes needs Administrator rights or an active SpectraNetworkManager Engine service.\n\nClose SpectraNetworkManager and start it again with 'Run as administrator'.");
            return;
        }

        var answer = MessageBox.Show(this,
            "Undo everything SpectraNetworkManager changed in Windows Firewall?\n\n" +
            "- strict mode is switched off\n" +
            "- every firewall rule SpectraNetworkManager created (blocks and allows) is removed\n\n" +
            "Your 'Allowed' decisions stay in SpectraNetworkManager's list; block decisions are cleared.",
            "Panic: undo all changes", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        if (_engineClient?.IsConnected == true)
        {
            try
            {
                await _engineClient.SendRequestAsync(IpcConstants.Actions.Panic);
                StatusText.Text = "Panic command executed via SpectraNetworkManager Engine service. All defaults restored.";
                UpdateStrictUi();
                AfterDecision();
                return;
            }
            catch (Exception ex)
            {
                Error("Engine panic request failed", ex);
            }
        }

        try
        {
            // Restore the default first, so nothing stays locked while the rules are being removed.
            if (_strict.State.Phase != StrictPhase.Off || _strict.WasUnreadable)
                await DisableStrictAsync();

            await _dnsSwitch.RestoreAllAsync();

            int removed = await Task.Run(() => _enforcer.RemoveAll());
            int cleared = _rules.RemoveWhere(r => r.Action == RuleAction.Block);
            StatusText.Text = $"Removed {removed} firewall rules and cleared {cleared} block decisions. Strict mode & system DNS restored.";
        }
        catch (Exception ex)
        {
            Error("Could not undo all changes", ex);
            return;
        }

        UpdateStrictUi();
        AfterDecision();
    }

    private void Info(string message) =>
        MessageBox.Show(this, message, "SpectraNetworkManager", MessageBoxButton.OK, MessageBoxImage.Information);

    private void Error(string what, Exception ex) =>
        MessageBox.Show(this, $"{what}.\n\n{ex.Message}", "SpectraNetworkManager", MessageBoxButton.OK, MessageBoxImage.Error);

    // ---- strict mode (block by default) ----------------------------------------------------

    private const int ConfirmSeconds = 60;

    private readonly StrictModeStore _strict = new(StrictModeStore.DefaultPath);
    private readonly Dictionary<string, string> _blockedDest = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _strictAwaiting = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _strictSeen = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _allowEnsured = new(StringComparer.OrdinalIgnoreCase);
    private long _lastBlockId;
    private DateTimeOffset _strictSince = DateTimeOffset.MinValue;
    private bool _blockPollBusy;
    private int _tickCount;

    private bool StrictActive => _strict.State.Phase == StrictPhase.Active;

    private void UpdateStrictUi()
    {
        var state = _strict.State;
        StrictBadge.Visibility = state.Phase == StrictPhase.Off ? Visibility.Collapsed : Visibility.Visible;

        StrictStatus.Text = state.Phase switch
        {
            StrictPhase.Active => "Strict mode is ON. Programs without permission cannot connect out.",
            StrictPhase.Pending => "Strict mode is waiting for confirmation.",
            _ => "Strict mode is OFF. Programs without a decision keep their network access; SpectraNetworkManager only watches and asks.",
        };

        StrictEnableButton.IsEnabled = state.Phase == StrictPhase.Off;
        StrictDisableButton.IsEnabled = state.Phase != StrictPhase.Off;
    }

    // Runs once at start: finishes or undoes whatever a previous run left behind.
    private async Task RecoverStrictStateAsync()
    {
        if (_strict.WasUnreadable)
            Info("The saved strict-mode state could not be read, so SpectraNetworkManager does not know whether strict mode is on.\n\nIf your network access is restricted, start SpectraNetworkManager as Administrator and press the PANIC button.");

        var state = _strict.State;
        if (state.Phase == StrictPhase.Pending)
        {
            if (!_isAdmin)
            {
                Info("Strict mode was switched on but never confirmed, and switching it off needs Administrator rights.\n\nClose SpectraNetworkManager and start it again with 'Run as administrator'. It will then switch strict mode off by itself.");
            }
            else
            {
                try
                {
                    string summary = await DisableStrictAsync();
                    Info("Strict mode was not confirmed last time, so it has been switched off.\n\n" + summary);
                }
                catch (Exception ex)
                {
                    Error("Strict mode was left unconfirmed and could not be switched off", ex);
                }
            }
        }
        else if (state.Phase == StrictPhase.Active)
        {
            _strictSince = DateTimeOffset.Now;
            if (_isAdmin) _lastBlockId = await Task.Run(LatestBlockId);
        }

        UpdateStrictUi();
    }

    private long LatestBlockId()
    {
        try
        {
            var recent = _blockLog.ReadRecent(TimeSpan.FromDays(1), 1);
            return recent.Count > 0 ? recent[0].RecordId : 0;
        }
        catch (Exception) { return 0; }
    }

    private async void OnStrictEnable(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            Info("Strict mode changes Windows Firewall, which needs Administrator rights.\n\nClose SpectraNetworkManager and start it again with 'Run as administrator'.");
            return;
        }
        if (_strict.State.Phase != StrictPhase.Off) return;

        // Programs that are online right now and nobody has judged yet (and whose signature is not alarming).
        var candidates = Programs
            .Where(p => p.Path.Length > 0 && p.Rule is null && !p.IsTrusted && p.InternetPeers > 0 && p.Signature is not { IsAlarming: true })
            .ToList();
        int existingAllows = _rules.All.Count(r => r.Action == RuleAction.Allow);

        var dialog = new StrictDialog(this, candidates.Count, existingAllows);
        if (dialog.ShowDialog() != true) return;

        ProgramRule[] snapshot = Array.Empty<ProgramRule>();
        try
        {
            StatusText.Text = "Switching on strict mode...";
            var previous = await Task.Run(() => _enforcer.ReadDefaultOutbound());

            if (dialog.AllowRunning)
            {
                snapshot = candidates.Select(c => new ProgramRule(c.Path, RuleAction.Allow, DateTimeOffset.Now, "allowed when strict mode was switched on")).ToArray();
                foreach (var rule in snapshot) _rules.Set(rule);
            }

            // Programs that get an allow rule: your Allow decisions, plus verified programs from trusted publishers that are running.
            var allowed = _rules.All.Where(r => r.Action == RuleAction.Allow).Select(r => r.Path)
                .Concat(Programs.Where(p => p.IsTrusted && p.Path.Length > 0).Select(p => p.Path))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var plan = StrictModePlanner.Plan(windows, Environment.ProcessPath, allowed);
            var mustSucceed = new HashSet<string>(
                StrictModePlanner.Essentials(windows, Environment.ProcessPath).Where(x => x.ProgramPath is not null).Select(x => x.ProgramPath!),
                StringComparer.OrdinalIgnoreCase);

            _lastBlockId = await Task.Run(LatestBlockId);

            // Written BEFORE anything changes: a crash from here on is undone at the next start.
            _strict.Save(new StrictModeState(StrictPhase.Pending, DateTimeOffset.Now.AddSeconds(ConfirmSeconds + 15), previous));
            UpdateStrictUi();

            List<string> warnings;
            try
            {
                warnings = await Task.Run(() => ApplyStrict(plan, mustSucceed, dialog.EnableAudit));
            }
            catch (Exception)
            {
                try { await DisableStrictAsync(); } catch (Exception) { /* reported below */ }
                UpdateStrictUi();
                throw;
            }

            _strictSince = DateTimeOffset.Now;      // blocks from now on count, including those during the confirmation

            var confirm = new StrictConfirmDialog(this, ConfirmSeconds);
            if (confirm.ShowDialog() == true)
            {
                _strict.Save(new StrictModeState(StrictPhase.Active, null, previous));
                _strictSeen.Clear();
                foreach (var p in allowed) _allowEnsured.Add(p);
                AddAlert(DateTimeOffset.Now, "STRICT MODE is on. Programs without permission are blocked; they will appear here and in the Ask bar.");
                StatusText.Text = "Strict mode is ON.";

                if (warnings.Count > 0)
                    Info("Strict mode is on, but some steps did not work:\n\n- " + string.Join("\n- ", warnings));
            }
            else
            {
                string summary = await DisableStrictAsync();
                StatusText.Text = "Strict mode was not confirmed and has been switched off.";
                Info("Strict mode has been switched off.\n\n" + summary);
            }
        }
        catch (Exception ex)
        {
            Error("Could not switch strict mode on. Windows Firewall was put back as it was", ex);
        }

        UpdateStrictUi();
        AfterDecision();
    }

    // Runs on a background thread (creating many firewall rules takes a moment).
    private List<string> ApplyStrict(IReadOnlyList<AllowSpec> plan, HashSet<string> mustSucceed, bool enableAudit)
    {
        var warnings = new List<string>();

        foreach (var spec in plan)
        {
            try
            {
                _enforcer.Allow(spec);
            }
            catch (Exception ex)
            {
                // Without these basic rules Windows itself would lose its network, so stop and undo.
                if (spec.ProgramPath is not null && mustSucceed.Contains(spec.ProgramPath))
                    throw new InvalidOperationException($"Could not allow {spec.Label}: {ex.Message}", ex);
                warnings.Add($"{spec.Label}: {ex.Message}");
            }
        }

        if (enableAudit)
        {
            var (ok, output) = AuditPolicy.EnableBlockedConnectionAuditing();
            if (!ok) warnings.Add("Auditing of blocked connections could not be switched on: " + output);
        }

        _enforcer.SetDefaultOutbound(ProfileDefaults.AllBlock);
        return warnings;
    }

    private async void OnStrictDisable(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            Info("Switching strict mode off changes Windows Firewall, which needs Administrator rights.");
            return;
        }

        var answer = MessageBox.Show(this,
            "Switch strict mode off?\n\nPrograms without a decision get their outgoing network access back.",
            "Strict mode", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.Yes);
        if (answer != MessageBoxResult.Yes) return;

        try
        {
            string summary = await DisableStrictAsync();
            StatusText.Text = "Strict mode is off. " + summary;
        }
        catch (Exception ex)
        {
            Error("Could not switch strict mode off", ex);
        }

        UpdateStrictUi();
        AfterDecision();
    }

    /// <summary>Restores the firewall defaults first (so nothing stays locked), then removes the allow rules, then records "off".</summary>
    private async Task<string> DisableStrictAsync()
    {
        var previous = _strict.State.Previous ?? ProfileDefaults.StandardWindows;
        bool backToAllow = previous is { Domain: ProfileDefaults.Allow, Private: ProfileDefaults.Allow, Public: ProfileDefaults.Allow };

        int removed = await Task.Run(() =>
        {
            _enforcer.SetDefaultOutbound(previous);
            return backToAllow ? _enforcer.RemoveAllAllowRules() : 0;
        });

        _strict.Save(StrictModeState.Off);
        _allowEnsured.Clear();
        _strictSeen.Clear();
        _strictAwaiting.Clear();

        return backToAllow
            ? $"Outgoing connections are allowed by default again ({removed} allow rules removed)."
            : "The previous firewall defaults were restored. The allow rules were kept, because outgoing connections were already blocked by default before strict mode.";
    }

    private void OnEnableAudit(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            Info("Changing the audit policy needs Administrator rights.");
            return;
        }

        try
        {
            var (ok, output) = AuditPolicy.EnableBlockedConnectionAuditing();
            Info(ok
                ? "Windows now records blocked connections in the Security log. The Firewall blocks view and strict mode can use it."
                : "Could not switch auditing on:\n\n" + output);
        }
        catch (Exception ex)
        {
            Error("Could not switch auditing on", ex);
        }
    }

    // ---- strict mode: what got blocked? ----------------------------------------------------

    private async Task PollBlockedAsync()
    {
        if (_blockPollBusy) return;
        _blockPollBusy = true;
        try
        {
            var events = await Task.Run(() => _blockLog.ReadAfter(_lastBlockId, 200));
            foreach (var ev in events)
            {
                _lastBlockId = Math.Max(_lastBlockId, ev.RecordId);

                if (ev.Inbound || ev.IsPacketDrop) continue;
                if (string.IsNullOrEmpty(ev.Application) || ev.Application.Equals("System", StringComparison.OrdinalIgnoreCase)) continue;
                if (ev.Time < _strictSince.AddSeconds(-30)) continue;      // blocked before strict mode was on

                HandleStrictBlocked(ev);
            }

            // A signature check that takes too long must not hold back the question forever.
            foreach (var path in _strictAwaiting.Where(kv => DateTimeOffset.Now - kv.Value > TimeSpan.FromSeconds(20)).Select(kv => kv.Key).ToList())
            {
                _strictAwaiting.Remove(path);
                DecideBlocked(path, StandingOf(path));
            }
        }
        catch (Exception)
        {
            // The Security log is not readable (auditing off, or no longer elevated): nothing to learn this time.
        }
        finally
        {
            _blockPollBusy = false;
        }
    }

    private void HandleStrictBlocked(BlockEvent ev)
    {
        string path = ev.Application;
        _blockedDest[path] = $"{ev.DestinationAddress}:{ev.DestinationPort}";

        var standing = StandingOf(path);
        if (standing.Rule?.Action == RuleAction.Block) return;          // you blocked it on purpose

        if (standing.Rule is null && !standing.IsTrusted)
        {
            if (!_strictSeen.Add(path)) return;                         // already asked or waiting

            if (standing.Signature is null)
            {
                _strictAwaiting[path] = DateTimeOffset.Now;            // wait for the signature result
                return;
            }
        }

        DecideBlocked(path, standing);
    }

    // A program was blocked by the default. Allowed or trusted: open the way. Otherwise: ask.
    private void DecideBlocked(string path, ProgramStanding standing)
    {
        string name = System.IO.Path.GetFileName(path);

        if (standing.Rule?.Action == RuleAction.Allow || standing.IsTrusted)
        {
            if (!_allowEnsured.Add(path)) return;                       // already done; do not loop

            string why = standing.Rule?.Action == RuleAction.Allow ? "your decision" : $"trusted publisher {standing.Signature?.Publisher}";
            _ = Task.Run(() => _enforcer.Allow(new AllowSpec(name, path, null))).ContinueWith(t =>
                Dispatcher.BeginInvoke(new Action(() => AddAlert(DateTimeOffset.Now,
                    t.IsFaulted ? $"Could not allow {name}: {t.Exception?.GetBaseException().Message}" : $"Allowed {name} ({why})."))));
            return;
        }

        var summary = new ProgramSummary(path, name, path, 0, 0, 0, 0, 0);
        string dest = _blockedDest.GetValueOrDefault(path, "?");
        AddAlert(DateTimeOffset.Now, standing.Signature is { IsAlarming: true } bad
            ? $"WARNING: strict mode blocked {name} ({bad.Describe()}) from connecting to {dest}"
            : $"Strict mode blocked {name} from connecting to {dest}");

        if (AskMode.IsChecked == true) EnqueueAsk(summary);
    }

    // ---- DNS sinkhole ----------------------------------------------------------------------

    private readonly DnsService _sink = DnsService.CreateDefault();
    private readonly SystemDnsSwitchManager _dnsSwitch;
    public ObservableCollection<AdapterListItem> DnsAdapters { get; } = new();
    private DnsLogEntry? _dnsLastTop;
    private bool _dnsBusy;
    private bool _dnsHistoryLoaded;
    private bool _isLoadingDnsSettings;

    private void OnAutoStartDnsChanged(object sender, RoutedEventArgs e)
    {
        if (_isLoadingDnsSettings) return;
        bool enabled = AutoStartDnsBox.IsChecked == true;
        _sink.Settings.AutoStart = enabled;
        _sink.SaveSettingsOnly(_sink.Settings);
        StatusText.Text = enabled ? "DNS auto-start enabled." : "DNS auto-start disabled.";
    }

    private void LoadDnsSettingsIntoUi()
    {
        _isLoadingDnsSettings = true;
        try
        {
        var c = _sink.Settings;
        DnsListenBox.Text = c.ListenAddress;
        DnsPortBox.Text = c.Port.ToString(CultureInfo.InvariantCulture);
        DnsUpstreamsBox.Text = string.Join(", ", c.Upstreams);
        DnsNullRadio.IsChecked = c.BlockMode == BlockMode.NullAddress;
        DnsNxRadio.IsChecked = c.BlockMode == BlockMode.NxDomain;
        InspectCnameBox.IsChecked = c.InspectCnames;
        BlockDohBox.IsChecked = c.BlockBrowserDoh;
        AutoStartDnsBox.IsChecked = c.AutoStart;
        RestrictClientsBox.IsChecked = c.RestrictClientsToLocalNetwork;
        DnsRateLimitBox.Text = c.RateLimitPerSecond.ToString(CultureInfo.InvariantCulture);
        AnonymizeIpsBox.IsChecked = c.AnonymizeClientIps;
        DoNotStoreDomainsBox.IsChecked = c.DoNotStoreDomains;
        RetentionDaysBox.Text = c.QueryHistoryRetentionDays.ToString(CultureInfo.InvariantCulture);
        ListsBox.Text = string.Join("\r\n", c.Lists.Select(l => (l.Enabled ? "" : "# ") + l.Name + " | " + l.Url));
        CustomBlockBox.Text = string.Join("\r\n", c.CustomBlock);
        CustomAllowBox.Text = string.Join("\r\n", c.CustomAllow);
        LocalRecordsBox.Text = string.Join("\r\n", c.LocalRecords.Select(r => $"{r.Domain} | {r.RecordType} | {r.Value}"));
        ConditionalForwardingBox.Text = string.Join("\r\n", c.ConditionalForwarding.Select(f => $"{f.DomainSuffix} | {f.TargetServer}"));
        DnsCustomRulesButton.Content = $"🛡️ Custom Rules ({c.CustomBlock.Count} blocked, {c.CustomAllow.Count} allowed)";
        }
        finally
        {
            _isLoadingDnsSettings = false;
        }
    }

    private bool TryReadDnsSettings(out DnsSettings settings, out string error)
    {
        settings = new DnsSettings();
        error = "";

        if (!int.TryParse(DnsPortBox.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int port))
        {
            error = "The port must be a number.";
            return false;
        }

        if (!int.TryParse(DnsRateLimitBox.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int rateLimit) || rateLimit < 0)
        {
            error = "The rate limit must be a number of queries per second (0 or greater).";
            return false;
        }

        if (!int.TryParse(RetentionDaysBox.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int retentionDays) || retentionDays < 0)
        {
            error = "The history retention days must be a number (0 or greater).";
            return false;
        }

        var lists = new List<BlocklistSource>();
        foreach (var raw in ListsBox.Text.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0) continue;

            bool enabled = !line.StartsWith('#');
            line = line.TrimStart('#').Trim();
            if (line.Length == 0) continue;

            int bar = line.IndexOf('|');
            string name = bar >= 0 ? line[..bar].Trim() : "";
            string url = bar >= 0 ? line[(bar + 1)..].Trim() : line;
            if (name.Length == 0) name = Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : url;
            lists.Add(new BlocklistSource(name, url, enabled));
        }

        static List<string> Lines(string text) =>
            text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();

        var localRecords = new List<LocalDnsRecord>();
        foreach (var raw in LocalRecordsBox.Text.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var parts = line.Split('|');
            if (parts.Length >= 3)
            {
                localRecords.Add(new LocalDnsRecord(parts[0].Trim(), parts[1].Trim(), parts[2].Trim()));
            }
        }

        var condFwd = new List<ConditionalForwardingRule>();
        foreach (var raw in ConditionalForwardingBox.Text.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var parts = line.Split('|');
            if (parts.Length >= 2)
            {
                condFwd.Add(new ConditionalForwardingRule(parts[0].Trim(), parts[1].Trim()));
            }
        }

        settings = new DnsSettings
        {
            AutoStart = AutoStartDnsBox.IsChecked == true,
            RestrictClientsToLocalNetwork = RestrictClientsBox.IsChecked == true,
            RateLimitPerSecond = rateLimit,
            QueryHistoryRetentionDays = retentionDays,
            AnonymizeClientIps = AnonymizeIpsBox.IsChecked == true,
            DoNotStoreDomains = DoNotStoreDomainsBox.IsChecked == true,
            ListenAddress = DnsListenBox.Text.Trim(),
            Port = port,
            Upstreams = DnsUpstreamsBox.Text.Split(new[] { ',', ';', ' ', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList(),
            BlockMode = DnsNxRadio.IsChecked == true ? BlockMode.NxDomain : BlockMode.NullAddress,
            InspectCnames = InspectCnameBox.IsChecked == true,
            BlockBrowserDoh = BlockDohBox.IsChecked == true,
            CacheEntries = _sink.Settings.CacheEntries,
            Lists = lists,
            CustomBlock = Lines(CustomBlockBox.Text),
            CustomAllow = Lines(CustomAllowBox.Text),
            LocalRecords = localRecords,
            ConditionalForwarding = condFwd,
        };
        return settings.Validate(out error);
    }

    private async Task StartDnsAsync()
    {
        if (_dnsBusy || _sink.IsRunning) return;
        _dnsBusy = true;
        try
        {
            if (!TryReadDnsSettings(out var settings, out string error))
            {
                Info(error);
                return;
            }

            await _sink.ApplySettingsAsync(settings);
            await _sink.StartAsync();
            StatusText.Text = $"DNS server started on {_sink.LocalEndPoint}.";
        }
        catch (SocketException ex)
        {
            Info($"The DNS server could not start: {ex.Message}\n\n" +
                 "Another program already uses this address and port. On Windows, 'Internet Connection Sharing', Hyper-V or WSL sometimes hold port 53. " +
                 "Try the listen address 127.0.0.1, or another port such as 5353 (then check it with 'Test my DNS server'; Windows' nslookup only talks to port 53).");
        }
        catch (Exception ex)
        {
            Error("The DNS server could not start", ex);
        }
        finally
        {
            _dnsBusy = false;
            RefreshDnsUi();
        }
    }

    private async void OnHeaderDnsClick(object sender, RoutedEventArgs e)
    {
        if (_dnsBusy) return;
        if (_sink.IsRunning)
        {
            OnDnsStop(sender, e);
        }
        else
        {
            await StartDnsAsync();
        }
    }

    private async void OnDnsStart(object sender, RoutedEventArgs e) => await StartDnsAsync();

    private void OnDnsStop(object sender, RoutedEventArgs e)
    {
        _sink.Stop();
        StatusText.Text = "DNS server stopped.";
        RefreshDnsUi();
    }

    private void OnDnsPauseClick(object sender, RoutedEventArgs e)
    {
        if (_sink.IsBlockingPaused)
        {
            _sink.ResumeBlocking();
            StatusText.Text = "DNS domain blocking resumed.";
            RefreshDnsUi();
            return;
        }

        var cm = new ContextMenu();
        void AddItem(string header, TimeSpan duration)
        {
            var mi = new MenuItem { Header = header };
            mi.Click += (_, _) =>
            {
                _sink.PauseBlocking(duration);
                StatusText.Text = $"DNS domain blocking paused for {duration.TotalMinutes:F0} minutes.";
                RefreshDnsUi();
            };
            cm.Items.Add(mi);
        }

        AddItem("Pause for 5 minutes", TimeSpan.FromMinutes(5));
        AddItem("Pause for 15 minutes", TimeSpan.FromMinutes(15));
        AddItem("Pause for 30 minutes", TimeSpan.FromMinutes(30));

        cm.PlacementTarget = (UIElement)sender;
        cm.IsOpen = true;
    }

    private async void OnDnsSelfTest(object sender, RoutedEventArgs e)
    {
        if (_dnsBusy) return;
        _dnsBusy = true;
        DnsTestButton.IsEnabled = false;
        try
        {
            StatusText.Text = "Testing the DNS server...";
            var result = await _sink.SelfTestAsync();
            StatusText.Text = result.Ok ? "DNS server test passed." : "DNS server test found a problem.";
            MessageBox.Show(this, result.Summary, result.Ok ? "DNS server test: OK" : "DNS server test: problem found",
                MessageBoxButton.OK, result.Ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            Error("The DNS server test could not run", ex);
        }
        finally
        {
            _dnsBusy = false;
            DnsTestButton.IsEnabled = true;
            RefreshDnsUi();
        }
    }

    private async void OnDnsSave(object sender, RoutedEventArgs e)
    {
        if (_dnsBusy) return;
        if (!TryReadDnsSettings(out var settings, out string error))
        {
            Info(error);
            return;
        }

        _dnsBusy = true;
        try
        {
            await _sink.ApplySettingsAsync(settings);
            StatusText.Text = _sink.IsRunning ? "DNS settings saved; the server was restarted." : "DNS settings saved.";
        }
        catch (SocketException ex)
        {
            Info($"The settings were saved, but the DNS server could not start again: {ex.Message}\n\nChoose another port or listen address and save again.");
        }
        catch (Exception ex)
        {
            Error("Could not save the DNS settings", ex);
        }
        finally
        {
            _dnsBusy = false;
            RefreshDnsUi();
        }
    }

    private async void OnDnsUpdateLists(object sender, RoutedEventArgs e)
    {
        if (_dnsBusy) return;
        if (!TryReadDnsSettings(out var settings, out string error))
        {
            Info(error);
            return;
        }

        _dnsBusy = true;
        try
        {
            StatusText.Text = "Downloading block lists...";
            await _sink.ApplySettingsAsync(settings);
            var results = await _sink.UpdateListsAsync();
            Info("Block lists:\n\n" + string.Join("\n", results.Select(r => $"{(r.Ok ? "OK " : "FAILED")}  {r.Name}: {r.Message}")) +
                 $"\n\n{_sink.BlockedDomainCount:N0} domains are blocked now.");
            StatusText.Text = $"Block lists updated: {_sink.BlockedDomainCount:N0} domains.";
        }
        catch (Exception ex)
        {
            Error("Could not update the block lists", ex);
        }
        finally
        {
            _dnsBusy = false;
            RefreshDnsUi();
        }
    }

    private void OnDnsFlush(object sender, RoutedEventArgs e)
    {
        _sink.Cache.Clear();
        StatusText.Text = "DNS cache emptied.";
    }

    private async void OnDnsClearLog(object sender, RoutedEventArgs e)
    {
        try
        {
            await _sink.ClearHistoryAsync();
            DnsRows.Clear();
            _dnsLastTop = null;
            _dnsHistoryLoaded = true;
            CloseDnsInspector();
            RefreshDnsUi();
            StatusText.Text = "DNS query log and persistent history cleared.";
        }
        catch (Exception ex)
        {
            Error("Could not clear DNS log", ex);
        }
    }

    private async void OnDnsAllow(object sender, RoutedEventArgs e) => await ChangeDnsRuleAsync(allow: true);

    private async void OnDnsBlock(object sender, RoutedEventArgs e) => await ChangeDnsRuleAsync(allow: false);

    private async Task ChangeDnsRuleAsync(bool allow)
    {
        var row = (DnsGrid.SelectedItem as DnsRow) ?? _inspectedDnsRow;
        if (row is null)
        {
            Info("Select a line in the query log first.");
            return;
        }

        try
        {
            if (allow) await _sink.AllowDomainAsync(row.Domain);
            else await _sink.BlockDomainAsync(row.Domain);

            LoadDnsSettingsIntoUi();
            StatusText.Text = allow ? $"{row.Domain} is always allowed now." : $"{row.Domain} is always blocked now.";
            if (DnsInspectorPanel.Visibility == Visibility.Visible)
            {
                ShowDnsInspector(row with { IsBlocked = !allow, Result = allow ? "ok" : "BLOCKED" });
            }
        }
        catch (Exception ex)
        {
            Error("Could not change the rule", ex);
        }
    }

    private void OnDnsGridSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_isUpdatingDnsRows) return;
        if (e.AddedItems.Count > 0 && e.AddedItems[0] is DnsRow added)
        {
            ShowDnsInspector(added);
        }
        else if (DnsGrid.SelectedItem is DnsRow row)
        {
            ShowDnsInspector(row);
        }
    }

    private void OnDnsGridPreviewMouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject dep)
        {
            var dataGridRow = FindVisualParent<DataGridRow>(dep);
            var row = dataGridRow?.DataContext as DnsRow
                      ?? (dep as FrameworkElement)?.DataContext as DnsRow
                      ?? (dep as FrameworkContentElement)?.DataContext as DnsRow;
            if (row != null)
            {
                ShowDnsInspector(row);
            }
        }
    }

    private static T? FindVisualParent<T>(DependencyObject? child) where T : DependencyObject
    {
        while (child != null)
        {
            if (child is T match) return match;
            child = child is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(child)
                : LogicalTreeHelper.GetParent(child);
        }
        return null;
    }

    private void OnCloseDnsInspector(object sender, RoutedEventArgs e) => CloseDnsInspector();

    private void CloseDnsInspector()
    {
        _inspectedDnsRow = null;
        DnsInspectorPanel.Visibility = Visibility.Collapsed;
        DnsGrid.UnselectAll();
        DnsGrid.SelectedItem = null;
    }

    private bool _dnsSidebarCollapsed;

    private void OnToggleDnsSidebar(object sender, RoutedEventArgs e)
    {
        _dnsSidebarCollapsed = !_dnsSidebarCollapsed;
        if (_dnsSidebarCollapsed)
        {
            DnsSidebarCol.Width = new GridLength(0);
            DnsSplitterCol.Width = new GridLength(0);
            DnsSidebarBorder.Visibility = Visibility.Collapsed;
            DnsToggleSidebarButton.Content = "⚙️ Settings & Adapters ▶";
            DnsToggleSidebarButton.ToolTip = "Show the Settings and Adapters sidebar";
        }
        else
        {
            DnsSidebarCol.Width = new GridLength(390);
            DnsSplitterCol.Width = new GridLength(10);
            DnsSidebarBorder.Visibility = Visibility.Visible;
            DnsToggleSidebarButton.Content = "◀ Hide Sidebar";
            DnsToggleSidebarButton.ToolTip = "Collapse the Settings and Adapters sidebar";
        }
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _lanDeviceNames = new();

    private string FormatClientDisplay(string client)
    {
        if (client == "127.0.0.1" || client == "::1" || client == "localhost")
        {
            return client;
        }
        if (_lanDeviceNames.TryGetValue(client, out var name) && !string.Equals(name, client, StringComparison.OrdinalIgnoreCase))
        {
            return $"{client} ({name})";
        }
        return client;
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, HashSet<string>> _resolvedIpsByDomain = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _resolvedDomainByIp = new(StringComparer.OrdinalIgnoreCase);

    private void RecordDomainResolution(string domain, string? detail)
    {
        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(detail)) return;
        string cleanDomain = domain.TrimEnd('.');

        var parts = detail.Split(new[] { ',', ';', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var p in parts)
        {
            if (IPAddress.TryParse(p.Trim(), out var ip))
            {
                string ipStr = ip.ToString();
                _resolvedDomainByIp[ipStr] = cleanDomain;
                _resolvedIpsByDomain.AddOrUpdate(cleanDomain,
                    _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ipStr },
                    (_, set) => { lock (set) { set.Add(ipStr); } return set; });
            }
        }
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (string Program, int Pid, DateTimeOffset LastSeen)> _recentProcessByHostOrIp = new(StringComparer.OrdinalIgnoreCase);

    private void RecordProcessSocket(string hostOrIp, string program, int pid)
    {
        if (pid <= 4 || string.IsNullOrWhiteSpace(hostOrIp) || string.IsNullOrWhiteSpace(program) || program.StartsWith("(none", StringComparison.OrdinalIgnoreCase)) return;
        _recentProcessByHostOrIp[hostOrIp] = (program, pid, DateTimeOffset.UtcNow);
    }

    private string ResolveInitiator(DnsRow row) =>
        ResolveInitiator(row.Domain, row.Client, row.Detail, row.IsBlocked);

    private string ResolveInitiator(string rawDomain, string client, string? detail, bool isBlocked)
    {
        if (client == "127.0.0.1" || client == "::1" || client == "localhost")
        {
            string domain = rawDomain.TrimEnd('.');

            if (_dnsEtw.TryGetCaller(domain, out var etwCaller))
            {
                return $"{etwCaller.Program} (PID {etwCaller.Pid})";
            }

            var matchingConn = Rows.FirstOrDefault(c =>
                !string.IsNullOrEmpty(c.Host) && (
                    c.Host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                    c.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase) ||
                    domain.EndsWith("." + c.Host, StringComparison.OrdinalIgnoreCase)));

            if (matchingConn != null)
            {
                return $"{matchingConn.Program} (PID {matchingConn.Pid})";
            }

            if (_resolvedIpsByDomain.TryGetValue(domain, out var domainIps))
            {
                lock (domainIps)
                {
                    var connByIp = Rows.FirstOrDefault(c =>
                        c.RemoteAddress != null && domainIps.Contains(c.RemoteAddress.ToString()));
                    if (connByIp != null)
                    {
                        return $"{connByIp.Program} (PID {connByIp.Pid})";
                    }
                }
            }

            var cutoff = DateTimeOffset.UtcNow.AddMinutes(-10);
            foreach (var kvp in _recentProcessByHostOrIp)
            {
                if (kvp.Value.LastSeen > cutoff)
                {
                    if (kvp.Key.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                        kvp.Key.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase) ||
                        domain.EndsWith("." + kvp.Key, StringComparison.OrdinalIgnoreCase) ||
                        (!string.IsNullOrEmpty(detail) && detail.Contains(kvp.Key)))
                    {
                        return $"{kvp.Value.Program} (PID {kvp.Value.Pid})";
                    }

                    if (domainIps != null)
                    {
                        lock (domainIps)
                        {
                            if (domainIps.Contains(kvp.Key))
                            {
                                return $"{kvp.Value.Program} (PID {kvp.Value.Pid})";
                            }
                        }
                    }
                }
            }

            if (!string.IsNullOrEmpty(detail))
            {
                var detailConn = Rows.FirstOrDefault(c =>
                    c.RemoteAddress != null && detail.Contains(c.RemoteAddress.ToString()));
                if (detailConn != null)
                {
                    return $"{detailConn.Program} (PID {detailConn.Pid})";
                }
            }

            try
            {
                string root = DomainIntelligence.Analyze(domain, false, false).RootDomain;
                string rootBase = root.Split('.')[0];
                if (!string.IsNullOrEmpty(rootBase) && rootBase.Length >= 4)
                {
                    var appMatch = Rows.FirstOrDefault(c =>
                        c.Program.StartsWith(rootBase, StringComparison.OrdinalIgnoreCase) ||
                        c.Program.Contains(rootBase, StringComparison.OrdinalIgnoreCase));
                    if (appMatch != null)
                    {
                        return $"{appMatch.Program} (PID {appMatch.Pid})";
                    }
                }
            }
            catch { }

            if (!domain.StartsWith("wpad", StringComparison.OrdinalIgnoreCase) &&
                !domain.Contains("msftconnecttest", StringComparison.OrdinalIgnoreCase) &&
                !domain.Contains("windowsupdate", StringComparison.OrdinalIgnoreCase))
            {
                var browser = Rows.FirstOrDefault(c =>
                    (c.Program.Equals("firefox.exe", StringComparison.OrdinalIgnoreCase) ||
                     c.Program.Equals("chrome.exe", StringComparison.OrdinalIgnoreCase) ||
                     c.Program.Equals("msedge.exe", StringComparison.OrdinalIgnoreCase) ||
                     c.Program.Equals("brave.exe", StringComparison.OrdinalIgnoreCase)) &&
                    (c.RemotePort == 443 || c.RemotePort == 80));
                if (browser != null)
                {
                    return $"{browser.Program} (PID {browser.Pid})";
                }
            }

            if (isBlocked)
            {
                return "svchost.exe (Blocked)";
            }

            return "svchost.exe (Windows Service)";
        }

        if (_lanDeviceNames.TryGetValue(client, out var cachedName))
        {
            return $"{cachedName} (LAN Device)";
        }

        _ = ResolveLanClientAsync(client);
        return $"LAN Device ({client})";
    }

    private async Task ResolveLanClientAsync(string clientIp)
    {
        if (_lanDeviceNames.ContainsKey(clientIp)) return;
        try
        {
            if (IPAddress.TryParse(clientIp, out var ip))
            {
                var hostEntry = await Dns.GetHostEntryAsync(ip);
                if (!string.IsNullOrWhiteSpace(hostEntry.HostName))
                {
                    _lanDeviceNames[clientIp] = hostEntry.HostName;
                    Dispatcher.Invoke(() =>
                    {
                        var current = _inspectedDnsRow ?? (DnsGrid.SelectedItem as DnsRow);
                        if (current != null && current.Client == clientIp)
                        {
                            InspectorClient.Text = FormatClientDisplay(current.Client);
                            InspectorInitiator.Text = $"{hostEntry.HostName} (LAN Device)";
                        }
                    });
                }
            }
        }
        catch
        {
            _lanDeviceNames[clientIp] = clientIp;
        }
    }

    private void ShowDnsInspector(DnsRow row)
    {
        if (row == null) return;
        _inspectedDnsRow = row;
        try
        {
            var analysis = DomainIntelligence.Analyze(row.Domain, row.IsBlocked, row.IsFailed);

            InspectorDomainText.Text = row.Domain;
            InspectorCategoryText.Text = analysis.CategoryName.ToUpperInvariant();

            bool isCustomBlock = _sink.IsCustomBlocked(row.Domain);
            bool isCustomAllow = _sink.IsCustomAllowed(row.Domain);

            if (isCustomBlock)
            {
                InspectorAdviceBadge.Background = new SolidColorBrush(Color.FromArgb(0x44, 0xFF, 0x2B, 0xD6));
                InspectorAdviceBadgeText.Foreground = (Brush)FindResource("Magenta");
                InspectorAdviceBadgeText.Text = "CUSTOM BLOCKED RULE";

                InspectorAdviceTitle.Foreground = (Brush)FindResource("Magenta");
                InspectorAdviceTitle.Text = "Manually Blocked by You:";
                InspectorAdviceDetail.Text = "This domain was explicitly added to your personal blocklist. Click 'Remove Custom Rule (Undo)' to revert.";

                InspectorBlockButton.Visibility = Visibility.Collapsed;
                InspectorAllowButton.Visibility = Visibility.Visible;
                InspectorRemoveCustomButton.Visibility = Visibility.Visible;
                InspectorRemoveCustomButton.Content = "✕ Remove from Blocklist (Undo)";
            }
            else if (isCustomAllow)
            {
                InspectorAdviceBadge.Background = new SolidColorBrush(Color.FromArgb(0x44, 0x22, 0xE8, 0xFF));
                InspectorAdviceBadgeText.Foreground = (Brush)FindResource("Cyan");
                InspectorAdviceBadgeText.Text = "CUSTOM WHITELIST RULE";

                InspectorAdviceTitle.Foreground = (Brush)FindResource("Cyan");
                InspectorAdviceTitle.Text = "Manually Whitelisted by You:";
                InspectorAdviceDetail.Text = "This domain is explicitly whitelisted in your personal allow list. Click 'Remove Custom Rule (Undo)' to revert.";

                InspectorBlockButton.Visibility = Visibility.Visible;
                InspectorAllowButton.Visibility = Visibility.Collapsed;
                InspectorRemoveCustomButton.Visibility = Visibility.Visible;
                InspectorRemoveCustomButton.Content = "✕ Remove from Whitelist (Undo)";
            }
            else
            {
                InspectorBlockButton.Visibility = Visibility.Visible;
                InspectorAllowButton.Visibility = Visibility.Visible;
                InspectorRemoveCustomButton.Visibility = Visibility.Collapsed;
                InspectorAdviceBadgeText.Text = analysis.AdviceTitle.ToUpperInvariant();

                Brush adviceBrush;
                Brush adviceBgBrush;
                switch (analysis.Advice)
                {
                    case BlockAdvice.SafeToBlock:
                        adviceBrush = (Brush)FindResource("Magenta");
                        adviceBgBrush = new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0x2B, 0xD6));
                        break;
                    case BlockAdvice.CautionBreakagePossible:
                        adviceBrush = (Brush)FindResource("Amber");
                        adviceBgBrush = new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0xB0, 0x20));
                        break;
                    case BlockAdvice.EssentialKeepAllowed:
                        adviceBrush = (Brush)FindResource("Cyan");
                        adviceBgBrush = new SolidColorBrush(Color.FromArgb(0x33, 0x22, 0xE8, 0xFF));
                        break;
                    default:
                        adviceBrush = row.IsBlocked ? (Brush)FindResource("Magenta") : (Brush)FindResource("Cyan");
                        adviceBgBrush = row.IsBlocked
                            ? new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0x2B, 0xD6))
                            : new SolidColorBrush(Color.FromArgb(0x33, 0x22, 0xE8, 0xFF));
                        break;
                }

                InspectorAdviceBadge.Background = adviceBgBrush;
                InspectorAdviceBadgeText.Foreground = adviceBrush;
                InspectorAdviceTitle.Foreground = adviceBrush;
                InspectorAdviceTitle.Text = analysis.AdviceTitle + ":";
                InspectorAdviceDetail.Text = analysis.AdviceDetail;
            }

            InspectorServiceName.Text = analysis.ServiceName;
            InspectorDescription.Text = analysis.Description;

            InspectorRootDomain.Text = analysis.RootDomain;
            InspectorClient.Text = FormatClientDisplay(row.Client);
            InspectorInitiator.Text = !string.IsNullOrEmpty(row.CallerProgram)
                ? row.CallerProgram
                : ResolveInitiator(row);
            InspectorQueryType.Text = row.Type;
            InspectorQueryTypeDesc.Text = row.TypeDescription;
            InspectorLatency.Text = $"{row.Ms} ms";
            InspectorOutcome.Text = row.Result;

            DnsInspectorPanel.Visibility = Visibility.Visible;
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"ShowDnsInspector failed for '{row.Domain}': {ex.Message}");
        }
    }

    private async void OnInspectorRemoveCustom(object sender, RoutedEventArgs e)
    {
        var row = _inspectedDnsRow ?? (DnsGrid.SelectedItem as DnsRow);
        if (row != null)
        {
            await _sink.RemoveCustomRuleAsync(row.Domain);
            LoadDnsSettingsIntoUi();
            RefreshDnsUi();
            ShowDnsInspector(row with { IsBlocked = false, Result = "ok" });
            StatusText.Text = $"Removed '{row.Domain}' from custom rules (undo completed).";
        }
    }

    private void OnOpenCustomRulesWindow(object sender, RoutedEventArgs e)
    {
        var win = new DnsCustomRulesWindow(_sink, () =>
        {
            LoadDnsSettingsIntoUi();
            RefreshDnsUi();
            var row = _inspectedDnsRow ?? (DnsGrid.SelectedItem as DnsRow);
            if (row != null)
            {
                ShowDnsInspector(row);
            }
        })
        {
            Owner = this
        };
        win.ShowDialog();
    }

    private async void OnInspectorBlock(object sender, RoutedEventArgs e)
    {
        var row = _inspectedDnsRow ?? (DnsGrid.SelectedItem as DnsRow);
        if (row != null)
        {
            await ChangeDnsRuleAsync(allow: false);
            ShowDnsInspector(row with { IsBlocked = true, Result = "BLOCKED" });
        }
    }

    private async void OnInspectorAllow(object sender, RoutedEventArgs e)
    {
        var row = _inspectedDnsRow ?? (DnsGrid.SelectedItem as DnsRow);
        if (row != null)
        {
            await ChangeDnsRuleAsync(allow: true);
            ShowDnsInspector(row with { IsBlocked = false, Result = "ok" });
        }
    }

    private void OnInspectorWhois(object sender, RoutedEventArgs e)
    {
        var row = _inspectedDnsRow ?? (DnsGrid.SelectedItem as DnsRow);
        if (row != null)
        {
            OpenWhoisLookup(row.Domain);
        }
    }

    private void OnInspectorLookup(object sender, RoutedEventArgs e)
    {
        var row = _inspectedDnsRow ?? (DnsGrid.SelectedItem as DnsRow);
        if (row != null)
        {
            OpenDomainOnlineLookup(row.Domain);
        }
    }

    private void OnInspectorCopy(object sender, RoutedEventArgs e)
    {
        var row = _inspectedDnsRow ?? (DnsGrid.SelectedItem as DnsRow);
        if (row != null)
        {
            CopyDomainToClipboard(row.Domain);
        }
    }

    private async void OnDnsContextMenuBlock(object sender, RoutedEventArgs e) => await ChangeDnsRuleAsync(allow: false);

    private async void OnDnsContextMenuAllow(object sender, RoutedEventArgs e) => await ChangeDnsRuleAsync(allow: true);

    private void OnDnsContextMenuWhois(object sender, RoutedEventArgs e)
    {
        if (DnsGrid.SelectedItem is DnsRow row)
        {
            OpenWhoisLookup(row.Domain);
        }
    }

    private void OnDnsContextMenuLookup(object sender, RoutedEventArgs e)
    {
        if (DnsGrid.SelectedItem is DnsRow row)
        {
            OpenDomainOnlineLookup(row.Domain);
        }
    }

    private void OnDnsContextMenuCopy(object sender, RoutedEventArgs e)
    {
        if (DnsGrid.SelectedItem is DnsRow row)
        {
            CopyDomainToClipboard(row.Domain);
        }
    }

    private void OpenWhoisLookup(string domain)
    {
        string d = DomainFilter.Normalize(domain).TrimStart('*').TrimStart('.');
        if (string.IsNullOrWhiteSpace(d)) return;
        string root = DomainIntelligence.GetRootDomain(d);
        if (!string.IsNullOrWhiteSpace(root)) d = root;

        try
        {
            string url = $"https://who.is/whois/{Uri.EscapeDataString(d)}";
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Error("Could not open browser for WHOIS lookup", ex);
        }
    }

    private void OpenDomainOnlineLookup(string domain)
    {
        string d = DomainFilter.Normalize(domain);
        if (string.IsNullOrWhiteSpace(d)) return;
        try
        {
            string url = $"https://www.virustotal.com/gui/domain/{Uri.EscapeDataString(d)}";
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Error("Could not open browser for domain lookup", ex);
        }
    }

    private void CopyDomainToClipboard(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return;
        try
        {
            System.Windows.Clipboard.SetText(domain);
            StatusText.Text = $"Copied '{domain}' to clipboard.";
        }
        catch
        {
            // Ignore clipboard lock errors
        }
    }

    private void OnDnsCheck(object sender, RoutedEventArgs e)
    {
        string text = DnsCheckBox.Text.Trim();
        if (text.Contains(' '))
        {
            var parts = text.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            string pattern = parts[0].Trim();
            string domain = parts[1].Trim();

            var builder = new DomainFilterBuilder();
            builder.AddCustom(pattern, allow: false);
            var filter = builder.Build();
            var dec = filter.Decide(domain);
            DnsCheckResult.Text = dec.Action == FilterAction.Blocked
                ? $"MATCH: '{domain}' is BLOCKED by '{pattern}'."
                : $"NO MATCH: '{domain}' is NOT blocked by '{pattern}'.";
            return;
        }

        DnsCheckResult.Text = _sink.Check(text);
    }

    private void OnPresetQuad9Doh(object sender, RoutedEventArgs e) =>
        DnsUpstreamsBox.Text = "https://9.9.9.9/dns-query, https://149.112.112.112/dns-query";

    private void OnPresetCloudflareDoh(object sender, RoutedEventArgs e) =>
        DnsUpstreamsBox.Text = "https://1.1.1.1/dns-query, https://1.0.0.1/dns-query";

    private void OnPresetGoogleDoh(object sender, RoutedEventArgs e) =>
        DnsUpstreamsBox.Text = "https://8.8.8.8/dns-query, https://8.8.4.4/dns-query";

    private void OnPresetQuad9Dot(object sender, RoutedEventArgs e) =>
        DnsUpstreamsBox.Text = "tls://9.9.9.9:853, tls://149.112.112.112:853";

    private void OnPresetStandard(object sender, RoutedEventArgs e) =>
        DnsUpstreamsBox.Text = "9.9.9.9, 1.1.1.1";

    private async void OnDnsExportCsv(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            FileName = "dns-query-history.csv",
            DefaultExt = ".csv"
        };
        if (dialog.ShowDialog(this) != true) return;

        try
        {
            using var writer = new StreamWriter(dialog.FileName, append: false, Encoding.UTF8);
            await _sink.ExportHistoryCsvAsync(writer);
            StatusText.Text = $"Exported query log to {System.IO.Path.GetFileName(dialog.FileName)}.";
        }
        catch (Exception ex)
        {
            Error("Could not export CSV file", ex);
        }
    }

    private async Task LoadInitialHistoryAsync()
    {
        try
        {
            var history = await _sink.LoadRecentHistoryAsync(300);
            if (history.Count > 0 && DnsRows.Count == 0)
            {
                foreach (var item in history)
                {
                    RecordDomainResolution(item.Domain, item.Detail);
                    string caller = ResolveInitiator(item.Domain, item.Client, item.Detail, item.Outcome == DnsOutcome.Blocked);
                    DnsRows.Add(DnsRow.From(item, caller));
                }
                _dnsLastTop = history[0];
            }
        }
        catch (Exception)
        {
            // Non-fatal
        }
    }

    private void OnDnsAllowLan(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            Info("Changing Windows Firewall needs Administrator rights.\n\nClose SpectraNetworkManager and start it again with 'Run as administrator'.");
            return;
        }
        if (Environment.ProcessPath is not string exe) return;
        if (!TryReadDnsSettings(out var settings, out string error))
        {
            Info(error);
            return;
        }

        var answer = MessageBox.Show(this,
            $"Allow devices on your local network to send DNS requests to this PC (port {settings.Port}, TCP and UDP)?\n\n" +
            "Only your own network is allowed (never the internet, never public networks such as cafes).\n\n" +
            "Remember to set the listen address to 0.0.0.0, otherwise only this PC can use the DNS server.",
            "Allow local network", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        try
        {
            _enforcer.AllowInboundDns(exe, settings.Port);
            StatusText.Text = $"Local network devices may now use the DNS server on port {settings.Port}.";
        }
        catch (Exception ex)
        {
            Error("Could not add the firewall rules", ex);
        }
    }

    private void OnDnsRemoveLan(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            Info("Changing Windows Firewall needs Administrator rights.");
            return;
        }
        if (Environment.ProcessPath is not string exe) return;

        try
        {
            _enforcer.RemoveInboundDns(exe);
            StatusText.Text = "Local network devices can no longer reach the DNS server.";
        }
        catch (Exception ex)
        {
            Error("Could not remove the firewall rules", ex);
        }
    }

    // ---- System DNS switch (point this PC to SpectraNetworkManager) -----------------------------------

    private async Task RecoverDnsSwitchStateAsync()
    {
        try
        {
            if (await _dnsSwitch.CheckStartupRecoveryAsync())
            {
                AddAlert(DateTimeOffset.Now, "Recovered from unexpected shutdown: original system DNS restored.");
            }
        }
        catch (Exception ex)
        {
            AddAlert(DateTimeOffset.Now, "Could not check DNS recovery state: " + ex.Message);
        }
    }

    private async Task RefreshAdaptersListAsync()
    {
        try
        {
            var adapters = await Task.Run(() => _dnsSwitch.GetAdaptersAsync());
            bool showVirtual = DnsShowVirtualAdaptersBox?.IsChecked == true;

            var filtered = adapters
                .Where(a => !a.IsVirtual || a.HasDefaultGateway || showVirtual)
                .ToList();

            // Safety fallback: if filtering virtual adapters leaves 0 results while adapters exist (e.g. VPN-only or custom virtual bridge), show all
            if (filtered.Count == 0 && adapters.Count > 0)
            {
                filtered = adapters.ToList();
            }

            bool anyGateway = filtered.Any(a => a.HasDefaultGateway);

            DnsAdapters.Clear();
            foreach (var a in filtered)
            {
                string dnsDesc = a.Ipv4Servers.Count > 0 ? string.Join(", ", a.Ipv4Servers) : (a.Ipv4IsDhcp ? "DHCP" : "None");
                if (a.Ipv6Servers.Count > 0) dnsDesc += $" / IPv6: {string.Join(", ", a.Ipv6Servers)}";

                bool isUp = a.Status.Equals("Up", StringComparison.OrdinalIgnoreCase);
                bool defaultSelected = anyGateway
                    ? (isUp && (a.HasDefaultGateway || !a.IsVirtual))
                    : (isUp && !a.IsVirtual);

                DnsAdapters.Add(new AdapterListItem
                {
                    InterfaceIndex = a.InterfaceIndex,
                    Name = a.Name,
                    Description = a.Description,
                    CurrentDns = dnsDesc,
                    IsWireless = a.IsWireless,
                    IsVirtual = a.IsVirtual,
                    HasDefaultGateway = a.HasDefaultGateway,
                    AdapterKind = a.AdapterKind,
                    IsSelected = defaultSelected,
                });
            }

            if (DnsAdapters.Count > 0 && !DnsAdapters.Any(x => x.IsSelected))
            {
                DnsAdapters[0].IsSelected = true;
            }

            if (DnsNoAdaptersHint != null)
            {
                DnsNoAdaptersHint.Visibility = DnsAdapters.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
        }
        catch (Exception ex)
        {
            AddAlert(DateTimeOffset.Now, "Could not query network adapters: " + ex.Message);
        }
    }

    private void UpdateDnsSwitchUi()
    {
        bool isActive = _dnsSwitch.IsActive;
        bool isPending = _dnsSwitch.IsPending;

        DnsApplySwitchButton.IsEnabled = !isActive && !isPending;
        DnsRestoreSwitchButton.IsEnabled = isActive || isPending;

        if (isPending)
        {
            DnsSwitchBanner.Visibility = Visibility.Visible;
            DnsSwitchBanner.BorderBrush = (Brush)FindResource("Amber");
            DnsSwitchStatus.Text = "System DNS switch is PENDING confirmation (60-second safety window)";
            DnsSwitchDetails.Text = $"Confirming connection to {_sink.LocalEndPoint}. Reverting automatically if unconfirmed.";
        }
        else if (isActive)
        {
            DnsSwitchBanner.Visibility = Visibility.Visible;
            DnsSwitchBanner.BorderBrush = (Brush)FindResource("Cyan");
            DnsSwitchStatus.Text = "This PC's DNS is pointing to SpectraNetworkManager (Active)";
            DnsSwitchDetails.Text = $"Protected adapters: {string.Join(", ", _dnsSwitch.State.Backups.Select(b => b.Name))}";
        }
        else
        {
            DnsSwitchBanner.Visibility = Visibility.Collapsed;
        }
    }

    private async void OnDnsRefreshAdapters(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        await RefreshAdaptersListAsync();
        UpdateDnsSwitchUi();
    }

    private void PromptRestartAsAdminForDns(string actionDescription)
    {
        var res = MessageBox.Show(this,
            $"{actionDescription} requires Administrator privileges.\n\n" +
            "Would you like to restart SpectraNetworkManager as Administrator now?",
            "Administrator Privileges Required",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (res == MessageBoxResult.Yes)
        {
            string exe = Environment.ProcessPath ?? "SpectraNetworkManager.exe";
            if (ElevationHelper.StartProcessElevated(exe))
            {
                _isExiting = true;
                _promptToast?.Close();
                _trayIcon?.Dispose();
                System.Windows.Application.Current.Shutdown(0);
            }
        }
    }

    private async void OnDnsSwitchApply(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            PromptRestartAsAdminForDns("Pointing Windows system DNS to SpectraNetworkManager");
            return;
        }

        if (!_sink.IsRunning)
        {
            await StartDnsAsync();
            if (!_sink.IsRunning)
            {
                return;
            }
        }

        var selected = DnsAdapters.Where(a => a.IsSelected).Select(a => a.InterfaceIndex).ToList();
        if (selected.Count == 0)
        {
            Info("Please tick at least one network adapter to change.");
            return;
        }

        bool onlyLocal = DnsFallbackModeBox.IsChecked != true;

        try
        {
            StatusText.Text = "Pointing selected network adapters to SpectraNetworkManager...";
            await _dnsSwitch.ApplyAsync(selected, onlyLocal);
            UpdateDnsSwitchUi();

            var confirm = new SystemDnsConfirmDialog(this, _dnsSwitch, SystemDnsSwitchManager.ConfirmTimeoutSeconds);
            if (confirm.ShowDialog() == true)
            {
                _dnsSwitch.Confirm();
                AddAlert(DateTimeOffset.Now, "System DNS confirmed. Windows is now using SpectraNetworkManager for DNS.");
                StatusText.Text = "System DNS is pointing to SpectraNetworkManager.";
            }
            else
            {
                StatusText.Text = "System DNS switch was cancelled. Reverting to original DNS...";
                await _dnsSwitch.RevertAsync();
                AddAlert(DateTimeOffset.Now, "System DNS switch cancelled: original DNS restored.");
                StatusText.Text = "Original system DNS restored.";
            }
        }
        catch (Exception ex)
        {
            Error("Could not change system DNS settings", ex);
            try { await _dnsSwitch.RevertAsync(); } catch { }
        }
        finally
        {
            await RefreshAdaptersListAsync();
            UpdateDnsSwitchUi();
        }
    }

    private async void OnDnsSwitchRestore(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            PromptRestartAsAdminForDns("Restoring Windows system DNS settings");
            return;
        }

        try
        {
            StatusText.Text = "Restoring original DNS on all adapters...";
            await _dnsSwitch.RestoreAllAsync();
            AddAlert(DateTimeOffset.Now, "Restored original DNS settings on all network adapters.");
            StatusText.Text = "Original system DNS restored.";
        }
        catch (Exception ex)
        {
            Error("Could not restore system DNS settings", ex);
        }
        finally
        {
            await RefreshAdaptersListAsync();
            UpdateDnsSwitchUi();
        }
    }

    // The badge is cheap and always current; the rest only matters while the DNS tab is visible.
    private void RefreshDnsUi()
    {
        DnsBadge.Visibility = _sink.IsRunning ? Visibility.Visible : Visibility.Collapsed;
        HeaderDnsButton.Content = _sink.IsRunning ? "⏹ Stop DNS" : "▶ Start DNS";
        HeaderDnsButton.Foreground = _sink.IsRunning ? (Brush)FindResource("Amber") : (Brush)FindResource("Cyan");
        HeaderDnsButton.ToolTip = _sink.IsRunning ? "Stop the running DNS Sinkhole Server" : "Start the DNS Sinkhole Server";
        if (DnsPanel.Visibility != Visibility.Visible) return;

        if (DnsAdapters.Count == 0)
        {
            _ = RefreshAdaptersListAsync();
        }

        DnsStartButton.IsEnabled = !_sink.IsRunning && !_dnsBusy;
        DnsStopButton.IsEnabled = _sink.IsRunning;
        DnsPauseButton.IsEnabled = _sink.IsRunning;
        DnsTestButton.IsEnabled = _sink.IsRunning && !_dnsBusy;
        UpdateDnsSwitchUi();

        if (!_dnsHistoryLoaded)
        {
            _dnsHistoryLoaded = true;
            _ = LoadInitialHistoryAsync();
        }

        var statuses = _sink.GetUpstreamStatuses();
        DnsUpstreamStatusText.Text = statuses.Count > 0
            ? "Upstreams: " + string.Join("  |  ", statuses.Select(s => $"{s.DisplayName}: {(s.IsHealthy ? "OK" : "ERR")}{(s.LastLatencyMs >= 0 ? $" ({s.LastLatencyMs}ms)" : "")}"))
            : "";

        if (_sink.IsBlockingPaused)
        {
            var remaining = _sink.BlockingPauseRemaining ?? TimeSpan.Zero;
            DnsPauseButton.Content = $"Resume ({remaining:mm\\:ss})";
            DnsPauseButton.Foreground = (Brush)FindResource("Amber");
            DnsStatus.Text = $"DNS server is RUNNING on {_sink.LocalEndPoint}  (Blocking paused: {remaining:mm\\:ss} left)";
        }
        else
        {
            DnsPauseButton.Content = "Pause blocking";
            DnsPauseButton.Foreground = (Brush)FindResource("Text");
            DnsStatus.Text = _sink.IsRunning
                ? $"DNS server is RUNNING on {_sink.LocalEndPoint}"
                : "DNS server is stopped. Point your DNS at it to start blocking.";
        }

        var stats = _sink.Activity.Snapshot();
        DnsCounters.Text =
            $"Queries {stats.Total:N0}   Blocked {stats.Blocked:N0} ({stats.BlockedPercent:F1}%)   Cached {stats.Cached:N0}   " +
            $"Forwarded {stats.Forwarded:N0}   Failed {stats.Failed:N0}   Domains on lists {_sink.BlockedDomainCount:N0}   Cache {_sink.Cache.Count:N0}";

        DnsNotes.Text = _sink.FilterInfo is { Notes.Count: > 0 } info ? string.Join("   |   ", info.Notes) : "";

        DnsTop.Text = "TOP BLOCKED\n" + FormatTop(stats.TopBlocked) + "\n\nTOP QUERIED\n" + FormatTop(stats.TopQueried) + "\n\nTOP CLIENTS\n" + FormatTop(stats.TopClients);

        // Add only the lines that are new since the last refresh (newest first).
        var recent = _sink.Activity.Recent(300);
        int known = _dnsLastTop is null ? recent.Count : recent.ToList().FindIndex(x => ReferenceEquals(x, _dnsLastTop));
        if (known < 0) known = recent.Count;
        _isUpdatingDnsRows = true;
        try
        {
            for (int i = known - 1; i >= 0; i--)
            {
                RecordDomainResolution(recent[i].Domain, recent[i].Detail);
                string caller = ResolveInitiator(recent[i].Domain, recent[i].Client, recent[i].Detail, recent[i].Outcome == DnsOutcome.Blocked);
                DnsRows.Insert(0, DnsRow.From(recent[i], caller));
            }
            while (DnsRows.Count > 500) DnsRows.RemoveAt(DnsRows.Count - 1);
        }
        finally
        {
            _isUpdatingDnsRows = false;
        }
        if (recent.Count > 0) _dnsLastTop = recent[0];
    }

    private static string FormatTop(IReadOnlyList<KeyValuePair<string, int>> top) =>
        top.Count == 0 ? "  -" : string.Join("\n", top.Select(kv => $"  {kv.Value,6:N0}  {kv.Key}"));

    // ---- host names ------------------------------------------------------------------------

    private void OnHostResolved(IPAddress ip, string? name)
    {
        if (string.IsNullOrEmpty(name)) return;
        // Called on a background thread; rows belong to the UI thread.
        Dispatcher.BeginInvoke(new Action(() =>
        {
            foreach (var row in Rows)
                if (row.RemoteAddress is not null && row.RemoteAddress.Equals(ip))
                {
                    row.Host = name;
                    RecordProcessSocket(name, row.Program, row.Pid);
                }
        }));
    }

    private void OnResolveHostsChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || ResolveHosts.IsChecked != true) return;
        foreach (var row in Rows)
            if (row.RemoteAddress is not null && row.Host.Length == 0)
                row.Host = _dns.Request(row.RemoteAddress) ?? "";
    }

    // ---- filtering and views ---------------------------------------------------------------

    private bool RowFilter(object item)
    {
        var r = (ConnectionRow)item;

        if (HideNoise.IsChecked == true && Display.IsTeardownNoise(r.StateValue)) return false;
        if (ShowListeners.IsChecked != true && r.StateValue == ConnectionState.Listen) return false;

        string q = SearchBox.Text.Trim();
        if (q.Length == 0) return true;

        return r.Program.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Local.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Remote.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Host.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Path.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Signer.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Pid.ToString().Contains(q, StringComparison.Ordinal);
    }

    private bool ProgramFilter(object item)
    {
        var p = (ProgramRow)item;
        string q = ProgramsSearchBox?.Text.Trim() ?? "";
        if (q.Length == 0) return true;
        return p.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
            || p.Path.Contains(q, StringComparison.OrdinalIgnoreCase)
            || p.Signer.Contains(q, StringComparison.OrdinalIgnoreCase)
            || p.Verdict.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private bool StartupFilter(object item)
    {
        var s = (StartupRow)item;
        string q = StartupSearchBox?.Text.Trim() ?? "";
        if (q.Length == 0) return true;
        return s.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
            || s.Command.Contains(q, StringComparison.OrdinalIgnoreCase)
            || s.Publisher.Contains(q, StringComparison.OrdinalIgnoreCase)
            || s.Location.Contains(q, StringComparison.OrdinalIgnoreCase)
            || s.Status.Contains(q, StringComparison.OrdinalIgnoreCase)
            || s.FirewallStatus.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    // These handlers can fire while the XAML is still being loaded, so ignore them until the window is ready.
    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        _rowsView.Refresh();
    }

    private void OnProgramsFilterChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        _programsView.Refresh();
    }

    private void OnStartupFilterChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        _startupView.Refresh();
    }

    private async void OnViewChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        ConnectionsPanel.Visibility = ConnectionsTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ProgramsPanel.Visibility = ProgramsTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        StartupPanel.Visibility = StartupTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        TrafficPanel.Visibility = TrafficTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        RulesPanel.Visibility = RulesTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        StrictPanel.Visibility = StrictTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        DnsPanel.Visibility = DnsTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        BlocksPanel.Visibility = BlocksTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;

        if (StartupTab.IsChecked == true) RefreshStartupItems();
        if (StrictTab.IsChecked == true) UpdateStrictUi();
        if (DnsTab.IsChecked == true) RefreshDnsUi();
        if (RulesTab.IsChecked == true) await RefreshRulesAsync();
        if (TrafficTab.IsChecked == true) await RefreshTrafficAsync();
        if (BlocksTab.IsChecked == true) await LoadBlocksAsync();
    }

    // ---- Startup Manager -------------------------------------------------------------------

    private string DescribeStartupFirewall(string? exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return "-";
        var rule = _rules.Find(exePath);
        if (rule == null) return "No rule";
        return rule.Action == RuleAction.Block ? "Blocked" : "Allowed";
    }

    private void RefreshStartupItems()
    {
        try
        {
            var entries = StartupManager.GetAllEntries();
            var selectedId = (StartupGrid.SelectedItem as StartupRow)?.Id;

            StartupItems.Clear();
            foreach (var entry in entries)
            {
                SignatureInfo? sig = null;
                if (!string.IsNullOrWhiteSpace(entry.ExecutablePath) && File.Exists(entry.ExecutablePath))
                {
                    sig = _signatures.TryGet(entry.ExecutablePath);
                }

                string fw = DescribeStartupFirewall(entry.ExecutablePath);
                StartupItems.Add(new StartupRow(entry, sig, fw));
            }

            if (selectedId != null)
            {
                StartupGrid.SelectedItem = StartupItems.FirstOrDefault(r => r.Id == selectedId);
            }

            int enabledCount = StartupItems.Count(s => !s.IsDisabled);
            int disabledCount = StartupItems.Count(s => s.IsDisabled);
            StatusText.Text = $"Startup Manager: {StartupItems.Count} auto-start item(s) found ({enabledCount} enabled, {disabledCount} disabled).";
        }
        catch (Exception ex)
        {
            Error("Could not scan startup items", ex);
        }
    }

    private StartupRow? SelectedStartupItem()
    {
        if (StartupGrid.SelectedItem is StartupRow row) return row;
        Info("Select a startup item in the list first.");
        return null;
    }

    private void OnRefreshStartupItems(object sender, RoutedEventArgs e) => RefreshStartupItems();

    private async void OnDisableStartupItem(object sender, RoutedEventArgs e)
    {
        var row = SelectedStartupItem();
        if (row is null) return;
        if (row.IsDisabled)
        {
            Info($"\"{row.Name}\" is already disabled.");
            return;
        }

        var res = await StartupManager.SetEnabledAsync(row.Entry, enable: false);
        if (!res.Success)
        {
            Info(res.Message);
            return;
        }

        RefreshStartupItems();
        StatusText.Text = res.Message;
    }

    private async void OnEnableStartupItem(object sender, RoutedEventArgs e)
    {
        var row = SelectedStartupItem();
        if (row is null) return;
        if (!row.IsDisabled)
        {
            Info($"\"{row.Name}\" is already enabled.");
            return;
        }

        var res = await StartupManager.SetEnabledAsync(row.Entry, enable: true);
        if (!res.Success)
        {
            Info(res.Message);
            return;
        }

        RefreshStartupItems();
        StatusText.Text = res.Message;
    }

    private async void OnDeleteStartupItem(object sender, RoutedEventArgs e)
    {
        var row = SelectedStartupItem();
        if (row is null) return;

        var answer = MessageBox.Show(this,
            $"Permanently delete auto-start entry \"{row.Name}\"?\n\n" +
            $"Location: {row.Location}\n" +
            $"Command: {row.Command}\n\n" +
            "Tip: If you only want to turn it off temporarily so you can re-enable it later, use 'Turn Off (Disable)' instead.",
            "Remove Startup Item Permanently", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        var res = await StartupManager.DeleteEntryAsync(row.Entry);
        if (!res.Success)
        {
            Info(res.Message);
            return;
        }

        RefreshStartupItems();
        StatusText.Text = res.Message;
    }

    private void OnBlockStartupItem(object sender, RoutedEventArgs e)
    {
        var row = SelectedStartupItem();
        if (row is null) return;

        if (string.IsNullOrWhiteSpace(row.ExecutablePath) || !File.Exists(row.ExecutablePath))
        {
            Info($"Could not locate a valid executable file on disk for \"{row.Name}\":\n\n{row.Command}");
            return;
        }

        var existing = _rules.Find(row.ExecutablePath);
        if (TryBlock(row.ExecutablePath, row.Name, existing))
        {
            AfterDecision();
            RefreshStartupItems();
        }
    }

    private void OnOpenStartupLocation(object sender, RoutedEventArgs e)
    {
        var row = SelectedStartupItem();
        if (row is null) return;

        string targetPath = !string.IsNullOrWhiteSpace(row.ExecutablePath) && File.Exists(row.ExecutablePath)
            ? row.ExecutablePath
            : row.Command;

        try
        {
            if (File.Exists(targetPath))
            {
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{targetPath}\"");
            }
            else
            {
                Info($"The file was not found on disk:\n\n{targetPath}");
            }
        }
        catch (Exception ex)
        {
            Error("Could not open file location", ex);
        }
    }

    private void OnCopyStartupCommand(object sender, RoutedEventArgs e)
    {
        var row = SelectedStartupItem();
        if (row is null || string.IsNullOrWhiteSpace(row.Command)) return;
        try
        {
            System.Windows.Clipboard.SetText(row.Command);
            StatusText.Text = $"Copied startup command to clipboard: {row.Command}";
        }
        catch { }
    }

    // ---- firewall blocks -------------------------------------------------------------------

    private async void OnRefreshBlocks(object sender, RoutedEventArgs e) => await LoadBlocksAsync();

    private async Task LoadBlocksAsync()
    {
        RefreshBlocksButton.IsEnabled = false;
        BlocksHint.Text = "Reading the Security log...";
        try
        {
            var events = await Task.Run(() => _blockLog.ReadRecent(TimeSpan.FromHours(1), 500));
            Blocks.Clear();
            foreach (var ev in events) Blocks.Add(BlockRow.From(ev));

            string wfpStatus = _blockLog.IsNativeSubscribed ? " (real-time WFP active)" : "";
            BlocksHint.Text = events.Count > 0
                ? $"{events.Count} blocked connections in the last hour (newest first){wfpStatus}."
                : (_blockLog.IsNativeSubscribed
                    ? "Nothing blocked in the last hour (real-time WFP active)."
                    : "Nothing blocked in the last hour. If you expected blocks, enable auditing once: see README, section \"Firewall blocks\".");
        }
        catch (UnauthorizedAccessException ex)
        {
            BlocksHint.Text = ex.Message;
        }
        catch (Exception ex)
        {
            BlocksHint.Text = "Could not read blocks: " + ex.Message;
        }
        finally
        {
            RefreshBlocksButton.IsEnabled = true;
        }
    }

    // ---- system tray & notifications --------------------------------------------------------

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_isExiting)
        {
            e.Cancel = true;
            Hide();
            if (!_trayBalloonShown && _trayIcon != null)
            {
                _trayBalloonShown = true;
                if (_appSettings.Settings.NotificationSoundEnabled)
                {
                    _trayIcon.ShowBalloonTip(3000, "SpectraNetworkManager", "SpectraNetworkManager is minimized to your system tray.", System.Windows.Forms.ToolTipIcon.Info);
                }
            }
            return;
        }
        _blockLog.Dispose();
        _trayIcon?.Dispose();
        base.OnClosing(e);
    }

    private void InitSystemTray()
    {
        try
        {
            _trayIcon = new System.Windows.Forms.NotifyIcon
            {
                Text = "SpectraNetworkManager - Network Monitor",
                Visible = true,
                Icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? "") ?? System.Drawing.SystemIcons.Shield
            };

            var menu = new System.Windows.Forms.ContextMenuStrip();
            menu.Items.Add("Show SpectraNetworkManager", null, (_, _) => RestoreFromTray());
            menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());

            _trayAlwaysOnTopItem = new System.Windows.Forms.ToolStripMenuItem("Always on Top")
            {
                Checked = _appSettings.Settings.AlwaysOnTop,
                CheckOnClick = true
            };
            _trayAlwaysOnTopItem.CheckedChanged += (_, _) =>
            {
                Dispatcher.Invoke(() =>
                {
                    AlwaysOnTopCheck.IsChecked = _trayAlwaysOnTopItem.Checked;
                });
            };
            menu.Items.Add(_trayAlwaysOnTopItem);

            _traySoundItem = new System.Windows.Forms.ToolStripMenuItem("Alert Sounds")
            {
                Checked = _appSettings.Settings.NotificationSoundEnabled,
                CheckOnClick = true
            };
            _traySoundItem.CheckedChanged += (_, _) =>
            {
                Dispatcher.Invoke(() =>
                {
                    NotificationSoundCheck.IsChecked = _traySoundItem.Checked;
                });
            };
            menu.Items.Add(_traySoundItem);
            menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());

            var pauseDns = new System.Windows.Forms.ToolStripMenuItem("Pause DNS Blocking");
            pauseDns.DropDownItems.Add("5 Minutes", null, async (_, _) => await PauseDnsBlockingAsync(5));
            pauseDns.DropDownItems.Add("30 Minutes", null, async (_, _) => await PauseDnsBlockingAsync(30));
            pauseDns.DropDownItems.Add("1 Hour", null, async (_, _) => await PauseDnsBlockingAsync(60));
            menu.Items.Add(pauseDns);

            menu.Items.Add("Resume DNS Blocking", null, async (_, _) => await ResumeDnsBlockingAsync());
            menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());

            menu.Items.Add("Panic: Revert All Changes", null, async (_, _) => await TriggerPanicAsync());
            menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());

            if (_isAdmin)
            {
                menu.Items.Add("Switch to Normal Mode", null, (_, _) => Dispatcher.Invoke(() => OnSwitchElevationClick(this, new RoutedEventArgs())));
            }
            else
            {
                menu.Items.Add("Switch to Administrator", null, (_, _) => Dispatcher.Invoke(() => OnSwitchElevationClick(this, new RoutedEventArgs())));
            }
            menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());

            menu.Items.Add("Check for Updates", null, async (_, _) => await CheckUpdatesAsync(manual: true));
            menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());

            menu.Items.Add("Exit SpectraNetworkManager", null, (_, _) =>
            {
                _isExiting = true;
                Close();
            });

            _trayIcon.ContextMenuStrip = menu;
            _trayIcon.DoubleClick += (_, _) => RestoreFromTray();
            _trayIcon.BalloonTipClicked += (_, _) => RestoreFromTray();
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogError("Failed to initialize system tray icon", ex);
        }
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private async Task PauseDnsBlockingAsync(int minutes)
    {
        if (_engineClient?.IsConnected == true)
        {
            await _engineClient.SendRequestAsync(IpcConstants.Actions.PauseDnsBlocking, minutes);
        }
        else
        {
            _sink.PauseBlocking(TimeSpan.FromMinutes(minutes));
        }
        RefreshDnsUi();
    }

    private async Task ResumeDnsBlockingAsync()
    {
        if (_engineClient?.IsConnected == true)
        {
            await _engineClient.SendRequestAsync(IpcConstants.Actions.ResumeDnsBlocking);
        }
        else
        {
            _sink.ResumeBlocking();
        }
        RefreshDnsUi();
    }

    private async Task TriggerPanicAsync()
    {
        if (_engineClient?.IsConnected == true)
        {
            await _engineClient.SendRequestAsync(IpcConstants.Actions.Panic);
        }
        else
        {
            if (_strict.State.Phase != StrictPhase.Off || _strict.WasUnreadable)
                await DisableStrictAsync();

            await _dnsSwitch.RestoreAllAsync();

            await Task.Run(() => _enforcer.RemoveAll());
            _rules.RemoveWhere(r => r.Action == RuleAction.Block);
        }
        UpdateStrictUi();
        AfterDecision();
    }

    // ---- bandwidth & traffic ----------------------------------------------------------------

    private void UpdateBandwidthDisplay(IReadOnlyList<ProcessBandwidthSample> samples)
    {
        if (samples == null || samples.Count == 0) return;

        var byPid = samples.ToDictionary(s => s.Pid);

        foreach (var row in _rows.Values)
        {
            if (byPid.TryGetValue(row.Pid, out var s))
            {
                row.UpdateSpeed(s.BytesReceivedPerSec, s.BytesSentPerSec);
            }
            else
            {
                row.UpdateSpeed(0, 0);
            }
        }

        // Aggregate bandwidth per program (matching main and all child processes)
        var programTotals = new Dictionary<string, (long In, long Out)>(StringComparer.OrdinalIgnoreCase);

        foreach (var s in samples)
        {
            var proc = _lastConnections.FirstOrDefault(c => c.Connection.ProcessId == s.Pid)?.Process
                       ?? _monitor.Resolver.Resolve(s.Pid);

            if (proc != null)
            {
                if (!string.IsNullOrWhiteSpace(proc.Path))
                {
                    var cur = programTotals.GetValueOrDefault(proc.Path);
                    programTotals[proc.Path] = (cur.In + s.BytesReceivedPerSec, cur.Out + s.BytesSentPerSec);
                }
                if (!string.IsNullOrWhiteSpace(proc.Name))
                {
                    var cur = programTotals.GetValueOrDefault(proc.Name);
                    programTotals[proc.Name] = (cur.In + s.BytesReceivedPerSec, cur.Out + s.BytesSentPerSec);
                }
            }
        }

        foreach (var pRow in _programRows.Values)
        {
            long inTotal = 0;
            long outTotal = 0;

            if (!string.IsNullOrWhiteSpace(pRow.Path) && programTotals.TryGetValue(pRow.Path, out var pathTotals))
            {
                inTotal = pathTotals.In;
                outTotal = pathTotals.Out;
            }
            else if (!string.IsNullOrWhiteSpace(pRow.Name) && programTotals.TryGetValue(pRow.Name, out var nameTotals))
            {
                inTotal = nameTotals.In;
                outTotal = nameTotals.Out;
            }
            else if (!string.IsNullOrWhiteSpace(pRow.Key) && programTotals.TryGetValue(pRow.Key, out var keyTotals))
            {
                inTotal = keyTotals.In;
                outTotal = keyTotals.Out;
            }

            pRow.UpdateSpeed(inTotal, outTotal);
        }
    }

    private async void OnTrafficRangeChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        if (TrafficRange1h.IsChecked == true) _trafficHours = 1;
        else if (TrafficRange24h.IsChecked == true) _trafficHours = 24;
        else if (TrafficRange7d.IsChecked == true) _trafficHours = 168;

        await RefreshTrafficAsync();
    }

    private async void OnRefreshTraffic(object sender, RoutedEventArgs e) => await RefreshTrafficAsync();

    private async Task RefreshTrafficAsync()
    {
        try
        {
            IReadOnlyList<ProgramTrafficSummary> topList;
            IReadOnlyList<ConnectionHistoryRecord> connList;

            if (_engineClient?.IsConnected == true)
            {
                topList = await _engineClient.SendRequestAsync<List<ProgramTrafficSummary>>(
                    IpcConstants.Actions.GetTopTalkers, _trafficHours) ?? (IReadOnlyList<ProgramTrafficSummary>)Array.Empty<ProgramTrafficSummary>();

                connList = await _engineClient.SendRequestAsync<List<ConnectionHistoryRecord>>(
                    IpcConstants.Actions.GetConnectionHistory, 300) ?? (IReadOnlyList<ConnectionHistoryRecord>)Array.Empty<ConnectionHistoryRecord>();
            }
            else
            {
                topList = await _historyDb.GetTopTalkersAsync(TimeSpan.FromHours(_trafficHours));
                connList = await _historyDb.GetRecentConnectionsAsync(300);
            }

            TopTalkers.Clear();
            foreach (var t in topList)
            {
                TopTalkers.Add(new TopTalkerViewModel(t.Program, t.TotalBytesIn, t.TotalBytesOut, t.LastActivity));
            }

            ConnectionHistory.Clear();
            foreach (var c in connList)
            {
                ConnectionHistory.Add(new ConnectionHistoryViewModel(c.Program, c.Remote, c.Port, c.Proto, c.FirstSeen, c.LastSeen));
            }
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogError("Failed to refresh traffic stats", ex);
        }
    }

    private void OnExportTraffic(object sender, RoutedEventArgs e)
    {
        try
        {
            var sfd = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"spectranetworkmanager-traffic-{DateTime.Now:yyyyMMdd-HHmmss}",
                DefaultExt = ".csv",
                Filter = "CSV Table (*.csv)|*.csv|JSON Data (*.json)|*.json|All files (*.*)|*.*",
                FilterIndex = 1
            };

            if (sfd.ShowDialog(this) == true)
            {
                string ext = System.IO.Path.GetExtension(sfd.FileName).ToLowerInvariant();
                if (ext == ".json" || (string.IsNullOrEmpty(ext) && sfd.FilterIndex == 2))
                {
                    var payload = new
                    {
                        ExportedAt = DateTimeOffset.UtcNow,
                        TopTalkers = TopTalkers,
                        RecentConnections = ConnectionHistory
                    };
                    string json = System.Text.Json.JsonSerializer.Serialize(payload, IndentedJsonOptions);
                    File.WriteAllText(sfd.FileName, json, System.Text.Encoding.UTF8);
                }
                else
                {
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("Program,BytesIn,BytesOut,TotalBytes,LastActive");
                    foreach (var t in TopTalkers)
                    {
                        sb.AppendLine($"\"{t.Program.Replace("\"", "\"\"")}\",{t.BytesIn},{t.BytesOut},{t.TotalBytes},\"{t.LastActive:O}\"");
                    }
                    sb.AppendLine();
                    sb.AppendLine("Program,Remote,Port,Protocol,FirstSeen,LastSeen");
                    foreach (var c in ConnectionHistory)
                    {
                        sb.AppendLine($"\"{c.Program.Replace("\"", "\"\"")}\",\"{c.Remote}\",{c.Port},\"{c.Proto}\",\"{c.FirstSeen:O}\",\"{c.LastSeen:O}\"");
                    }
                    File.WriteAllText(sfd.FileName, sb.ToString(), System.Text.Encoding.UTF8);
                }
                Info($"Traffic data exported to {sfd.FileName}");
            }
        }
        catch (Exception ex)
        {
            Info($"Failed to export traffic data: {ex.Message}");
        }
    }

    private void OnExportTrafficCsv(object sender, RoutedEventArgs e)
    {
        try
        {
            var sfd = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"spectranetworkmanager-traffic-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
                DefaultExt = ".csv",
                Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
            };

            if (sfd.ShowDialog(this) == true)
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine("Program,BytesIn,BytesOut,TotalBytes,LastActive");
                foreach (var t in TopTalkers)
                {
                    sb.AppendLine($"\"{t.Program.Replace("\"", "\"\"")}\",{t.BytesIn},{t.BytesOut},{t.TotalBytes},\"{t.LastActive:O}\"");
                }
                sb.AppendLine();
                sb.AppendLine("Program,Remote,Port,Protocol,FirstSeen,LastSeen");
                foreach (var c in ConnectionHistory)
                {
                    sb.AppendLine($"\"{c.Program.Replace("\"", "\"\"")}\",\"{c.Remote}\",{c.Port},\"{c.Proto}\",\"{c.FirstSeen:O}\",\"{c.LastSeen:O}\"");
                }
                File.WriteAllText(sfd.FileName, sb.ToString(), System.Text.Encoding.UTF8);
                Info($"Traffic data exported to {sfd.FileName}");
            }
        }
        catch (Exception ex)
        {
            Info($"Failed to export traffic CSV: {ex.Message}");
        }
    }

    private void OnExportTrafficJson(object sender, RoutedEventArgs e)
    {
        try
        {
            var sfd = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"spectranetworkmanager-traffic-{DateTime.Now:yyyyMMdd-HHmmss}.json",
                DefaultExt = ".json",
                Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
            };

            if (sfd.ShowDialog(this) == true)
            {
                var payload = new
                {
                    ExportedAt = DateTimeOffset.UtcNow,
                    TopTalkers = TopTalkers,
                    RecentConnections = ConnectionHistory
                };
                string json = System.Text.Json.JsonSerializer.Serialize(payload, IndentedJsonOptions);
                File.WriteAllText(sfd.FileName, json, System.Text.Encoding.UTF8);
                Info($"Traffic data exported to {sfd.FileName}");
            }
        }
        catch (Exception ex)
        {
            Info($"Failed to export traffic JSON: {ex.Message}");
        }
    }

    private static readonly System.Text.Json.JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };

    private void OnCopySupportInfo(object sender, RoutedEventArgs e)
    {
        try
        {
            string status = _engineClient?.IsConnected == true
                ? "Connected to Engine Service (LocalSystem)"
                : "Standalone (Local Process UI)";

            string report = SupportInfoGenerator.Generate(
                engineStatusSummary: status,
                ruleCount: _rules.All.Count,
                blocklistCount: _sink.BlockedDomainCount,
                options: new SupportInfoOptions(RedactUserPaths: true, RedactDomains: false));

            System.Windows.Clipboard.SetText(report);
            StatusText.Text = "Support diagnostic report copied to clipboard (personal paths redacted).";
            Info("Support diagnostic report copied to clipboard!\n\nPersonal user profile paths were automatically redacted (<redacted>).");
        }
        catch (Exception ex)
        {
            Info($"Failed to copy support report: {ex.Message}");
        }
    }

    private async void OnCheckUpdatesClick(object sender, RoutedEventArgs e)
    {
        await CheckUpdatesAsync(manual: true);
    }

    private void OnUpdateBadgeClick(object sender, RoutedEventArgs e)
    {
        if (_lastUpdateResult?.HtmlUrl is not null)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(_lastUpdateResult.HtmlUrl) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                Error("Could not open browser", ex);
            }
        }
    }

    private async Task CheckUpdatesAsync(bool manual)
    {
        string currentVer = typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        CheckUpdatesButton.IsEnabled = false;
        if (manual) StatusText.Text = "Checking GitHub Releases for updates...";

        try
        {
            var result = await _updateChecker.CheckForUpdatesAsync(currentVer);
            _lastUpdateResult = result;

            if (result.IsSuccess)
            {
                if (result.IsUpdateAvailable)
                {
                    UpdateBadge.Visibility = Visibility.Visible;
                    UpdateBadge.Content = $"Update: {result.LatestVersion}";
                    StatusText.Text = $"New version available: {result.LatestVersion}. Click 'Update' button to view.";

                    if (manual)
                    {
                        var choice = MessageBox.Show(this,
                            $"A new version of SpectraNetworkManager is available!\n\n" +
                            $"Current version: v{currentVer}\n" +
                            $"Latest version: {result.LatestVersion}\n" +
                            $"Release: {result.ReleaseName}\n\n" +
                            "Would you like to open the GitHub Releases page to download it?",
                            "SpectraNetworkManager Update Available", MessageBoxButton.YesNo, MessageBoxImage.Information);

                        if (choice == MessageBoxResult.Yes && result.HtmlUrl != null)
                        {
                            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(result.HtmlUrl) { UseShellExecute = true });
                        }
                    }
                }
                else
                {
                    UpdateBadge.Visibility = Visibility.Collapsed;
                    if (manual)
                    {
                        StatusText.Text = "SpectraNetworkManager is up to date.";
                        MessageBox.Show(this,
                            $"SpectraNetworkManager is up to date.\n\nYou are running the latest version (v{currentVer}).",
                            "SpectraNetworkManager Update Check", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
            }
            else if (manual)
            {
                StatusText.Text = "Update check failed.";
                MessageBox.Show(this,
                    $"Could not check for updates.\n\n{result.ErrorMessage}",
                    "SpectraNetworkManager Update Check", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            if (manual) Error("Failed to check for updates", ex);
        }
        finally
        {
            CheckUpdatesButton.IsEnabled = true;
        }
    }

    private void UpdateElevationUi()
    {
        if (_isAdmin)
        {
            AdminStateIcon.Text = "🛡️ ";
            AdminStateText.Text = "ADMINISTRATOR";
            AdminStateText.Foreground = (Brush)FindResource("Cyan");
            AdminStateBadge.BorderBrush = (Brush)FindResource("Cyan");
            AdminStateBadge.ToolTip = "Running with full Administrator privileges.\nFirewall rules, driver monitoring, and system DNS can be modified directly.";

            SwitchElevationButton.Content = "👤 Switch to Normal Mode";
            SwitchElevationButton.Foreground = (Brush)FindResource("Text");
            SwitchElevationButton.ToolTip = "Restart SpectraNetworkManager in standard user mode without Administrator privileges.";
        }
        else
        {
            AdminStateIcon.Text = "👤 ";
            AdminStateText.Text = "STANDARD USER";
            AdminStateText.Foreground = (Brush)FindResource("Amber");
            AdminStateBadge.BorderBrush = (Brush)FindResource("Amber");
            AdminStateBadge.ToolTip = "Running in Standard User mode.\nNot elevated: Blocking, some program names, and the Firewall blocks view need Administrator privileges.\nClick 'Switch to Administrator' to elevate.";

            SwitchElevationButton.Content = "🛡️ Switch to Administrator";
            SwitchElevationButton.Foreground = (Brush)FindResource("Cyan");
            SwitchElevationButton.ToolTip = "Restart SpectraNetworkManager with full Administrator privileges (prompts UAC elevation).";
        }

        AlwaysAdminCheck.IsChecked = _appSettings.Settings.AlwaysStartAsAdministrator;
    }

    private void OnSwitchElevationClick(object sender, RoutedEventArgs e)
    {
        string exe = Environment.ProcessPath ?? "SpectraNetworkManager.exe";

        if (!_isAdmin)
        {
            var res = MessageBox.Show(this,
                "Restart SpectraNetworkManager with Administrator privileges?\n\n" +
                "Windows will show a User Account Control (UAC) prompt to elevate.",
                "Switch to Administrator Mode",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (res != MessageBoxResult.Yes) return;

            if (ElevationHelper.StartProcessElevated(exe))
            {
                _isExiting = true;
                _promptToast?.Close();
            _trayIcon?.Dispose();
                System.Windows.Application.Current.Shutdown(0);
            }
        }
        else
        {
            if (_appSettings.Settings.AlwaysStartAsAdministrator)
            {
                var res = MessageBox.Show(this,
                    "SpectraNetworkManager is currently set to 'Always run as admin'.\n\n" +
                    "To switch to Normal mode, would you like to disable 'Always run as admin'?",
                    "Switch to Normal Mode",
                    MessageBoxButton.YesNoCancel,
                    MessageBoxImage.Question);

                if (res == MessageBoxResult.Cancel) return;

                if (res == MessageBoxResult.Yes)
                {
                    _appSettings.Save(_appSettings.Settings with { AlwaysStartAsAdministrator = false });
                    ElevationHelper.SetAlwaysRunAsAdminRegistry(exe, false);
                    AlwaysAdminCheck.IsChecked = false;

                    if (ElevationHelper.StartProcessUnelevated(exe))
                    {
                        _isExiting = true;
                        _promptToast?.Close();
            _trayIcon?.Dispose();
                        System.Windows.Application.Current.Shutdown(0);
                    }
                }
                else if (res == MessageBoxResult.No)
                {
                    if (ElevationHelper.StartProcessUnelevated(exe, "--normal"))
                    {
                        _isExiting = true;
                        _promptToast?.Close();
            _trayIcon?.Dispose();
                        System.Windows.Application.Current.Shutdown(0);
                    }
                }
            }
            else
            {
                var res = MessageBox.Show(this,
                    "Restart SpectraNetworkManager in Normal (Standard User) mode?",
                    "Switch to Normal Mode",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (res != MessageBoxResult.Yes) return;

                if (ElevationHelper.StartProcessUnelevated(exe))
                {
                    _isExiting = true;
                    _promptToast?.Close();
            _trayIcon?.Dispose();
                    System.Windows.Application.Current.Shutdown(0);
                }
            }
        }
    }

    private void OnAlwaysAdminChanged(object sender, RoutedEventArgs e)
    {
        bool enable = AlwaysAdminCheck.IsChecked == true;
        if (enable == _appSettings.Settings.AlwaysStartAsAdministrator) return;

        var updated = _appSettings.Settings with { AlwaysStartAsAdministrator = enable };
        try
        {
            _appSettings.Save(updated);
            string exe = Environment.ProcessPath ?? "SpectraNetworkManager.exe";
            ElevationHelper.SetAlwaysRunAsAdminRegistry(exe, enable);
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogError("Failed to save AlwaysStartAsAdministrator setting", ex);
        }
    }
    // ---- Live Bandwidth Speed Monitor --------------------------------------------------------

    private long _lastTotalBytesIn;
    private long _lastTotalBytesOut;
    private DateTimeOffset _lastBandwidthTime = DateTimeOffset.MinValue;
    private long _sessionBytesIn;
    private long _sessionBytesOut;
    private bool _bandwidthInitialized;

    private void UpdateLiveBandwidth()
    {
        try
        {
            long currentIn = 0;
            long currentOut = 0;
            int activeAdapters = 0;

            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                    ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                var stats = ni.GetIPStatistics();
                currentIn += stats.BytesReceived;
                currentOut += stats.BytesSent;
                activeAdapters++;
            }

            var now = DateTimeOffset.UtcNow;

            if (!_bandwidthInitialized)
            {
                _lastTotalBytesIn = currentIn;
                _lastTotalBytesOut = currentOut;
                _lastBandwidthTime = now;
                _bandwidthInitialized = true;
                return;
            }

            double seconds = (now - _lastBandwidthTime).TotalSeconds;
            if (seconds <= 0.2) return;

            long deltaIn = Math.Max(0, currentIn - _lastTotalBytesIn);
            long deltaOut = Math.Max(0, currentOut - _lastTotalBytesOut);

            _lastTotalBytesIn = currentIn;
            _lastTotalBytesOut = currentOut;
            _lastBandwidthTime = now;

            _sessionBytesIn += deltaIn;
            _sessionBytesOut += deltaOut;

            double dlSpeedPerSec = deltaIn / seconds;
            double ulSpeedPerSec = deltaOut / seconds;

            if (TrafficTab.IsChecked == true)
            {
                LiveDownloadSpeedText.Text = FormatBandwidthSpeed(dlSpeedPerSec);
                LiveUploadSpeedText.Text = FormatBandwidthSpeed(ulSpeedPerSec);
                SessionTrafficText.Text = Display.Bytes(_sessionBytesIn + _sessionBytesOut);
                LiveTrafficInterfaceText.Text = $"Active adapters: {activeAdapters} (DL: {Display.Bytes(_sessionBytesIn)}, UL: {Display.Bytes(_sessionBytesOut)})";
            }
        }
        catch
        {
            // Ignore transient network interface read failures
        }
    }

    private static string FormatBandwidthSpeed(double bytesPerSec)
    {
        if (bytesPerSec < 1024) return $"{bytesPerSec:F0} B/s";
        if (bytesPerSec < 1024 * 1024) return $"{bytesPerSec / 1024.0:F1} KB/s";
        if (bytesPerSec < 1024 * 1024 * 1024) return $"{bytesPerSec / (1024.0 * 1024.0):F2} MB/s";
        return $"{bytesPerSec / (1024.0 * 1024.0 * 1024.0):F2} GB/s";
    }

    private static bool IsAdministrator() => ElevationHelper.IsAdministrator();
}
