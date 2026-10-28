using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
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
using SpectraNetworkManager.Core.Ai;
using SpectraNetworkManager.Core.Audit;
using SpectraNetworkManager.Core.BrowserGuard;
using SpectraNetworkManager.Core.Devices;
using SpectraNetworkManager.Core.Ipc;
using SpectraNetworkManager.Core.Localization;
using SpectraNetworkManager.Platform.Windows;
using SpectraNetworkManager.Platform.Windows.Ai;
using SpectraNetworkManager.Platform.Windows.BrowserGuard;
using SpectraNetworkManager.Platform.Windows.Mobile;
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
    private readonly ExecutableHashCache _hashCache = new(ExecutableHashCache.DefaultPath);
    private readonly IpIntelligenceService _ipIntel = new();
    private readonly Dictionary<string, (ProgramSummary Summary, DateTimeOffset Since)> _awaiting = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _alarmed = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<ConnectionKey, ConnectionRow> _rows = new();
    private readonly Dictionary<string, ProgramRow> _programRows = new(StringComparer.OrdinalIgnoreCase);
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly ICollectionView _rowsView;
    private readonly ICollectionView _programsView;
    private readonly ICollectionView _startupView;
    private readonly ICollectionView _dnsView;
    private readonly bool _isAdmin = IsAdministrator();
    private DnsRow? _inspectedDnsRow;
    private ConnectionRow? _inspectedConnectionRow;
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
    private static readonly OncePerRunGate TrayHintGate = new();
    private int _trafficHours = 1;
    private readonly AppSettingsStore _appSettings = new();
    private readonly UpdateChecker _updateChecker = new();
    private UpdateCheckResult? _lastUpdateResult;
    private NetworkPromptToastWindow? _promptToast;
    private System.Windows.Forms.ToolStripMenuItem? _trayAlwaysOnTopItem;
    private System.Windows.Forms.ToolStripMenuItem? _traySoundItem;
    private DateTimeOffset _lastSoundTime = DateTimeOffset.MinValue;
    private readonly WindowsNeighborScanner _neighborScanner = new();
    private readonly NetworkScanner _scanner;
    private readonly LocalSocketInventory _localInventory;
    private CancellationTokenSource? _scanCts;
    private readonly QuarantineVault _quarantineVault = new();
    private readonly QuarantineManager _quarantineManager;
    private readonly HostsFileMonitor _hostsMonitor = new();
    private readonly PacketCaptureManager _packetCaptureManager;
    private string _packetProtocolFilter = "ALL";
    private string _packetSearchTerm = "";

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
    public ObservableCollection<DiscoveredDevice> DiscoveredDevices { get; } = new();
    public ObservableCollection<DiscoveredPort> SelectedDevicePorts { get; } = new();
    public ObservableCollection<PacketRow> CapturedPackets { get; } = new();
    public ICollectionView CapturedPacketsView { get; }
    public ObservableCollection<TvMobileDeviceRow> TvMobileDevices { get; } = new();
    public ObservableCollection<DnsRow> TvLanActivityRows { get; } = new();
    public ObservableCollection<BrowserGuardRuleRow> BrowserGuardRules { get; } = new();
    public ObservableCollection<AiInvestigationViewModel> AiHistory { get; } = new();
    public ObservableCollection<QuarantineSnapshot> QuarantinedItems { get; } = new();
    private readonly BrowserGuardManager _browserGuardManager;
    private readonly AiInvestigationDatabase _aiDb = new();
    private readonly AiInvestigationCoordinator _aiCoordinator;
    private InvestigationReport? _currentAiReport;
    private string? _aiSelectedPath;
    private int _aiSelectedPid;
    private MobileCompanionServer? _mobileServer;

    public MainWindow()
    {
        _browserGuardManager = new BrowserGuardManager();
        _aiCoordinator = new AiInvestigationCoordinator(
            _processResolver,
            _hashCache,
            _aiDb,
            new OllamaClient(
                endpointUrl: _appSettings.Settings.OllamaEndpoint,
                defaultModel: _appSettings.Settings.OllamaModel));
        _scanner = new NetworkScanner(_neighborScanner);
        _localInventory = new LocalSocketInventory(new IpHelperConnectionSource(), _processResolver);
        _dnsSwitch = new SystemDnsSwitchManager(null, null, () => _sink.LocalEndPoint);
        _quarantineManager = new QuarantineManager(_quarantineVault, _rules, _enforcer, new TcpConnectionTerminator(), _signatures);
        _hostsMonitor.StartMonitoring();
        _hostsMonitor.HostsFileChanged += OnHostsFileChanged;
        _packetCaptureManager = new PacketCaptureManager(MatchConnectionToProcess);
        _packetCaptureManager.BatchFlushed += OnPacketBatchFlushed;
        _packetCaptureManager.StatusChanged += OnPacketStatusChanged;
        CapturedPacketsView = CollectionViewSource.GetDefaultView(CapturedPackets);
        CapturedPacketsView.Filter = PacketRowFilter;
        InitializeComponent();
        UpdateHostsBannerUi(_hostsMonitor.GetStatus());
        TvMobileGrid.ItemsSource = TvMobileDevices;
        BrowserGuardGrid.ItemsSource = BrowserGuardRules;
        InitPacketCaptureInterfaces();
        InitTvMobileAndBrowserGuardUi();
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

        _dnsView = CollectionViewSource.GetDefaultView(DnsRows);
        _dnsView.Filter = DnsRowFilter;

        _dns.Resolved += OnHostResolved;
        _signatures.Verified += OnSignatureVerified;

        _promptToast = new NetworkPromptToastWindow();
        _promptToast.AllowRequested += OnToastAllow;
        _promptToast.BlockRequested += OnToastBlock;
        _promptToast.TrustRequested += OnToastTrust;
        _promptToast.LaterRequested += OnToastLater;
        _promptToast.InspectRequested += OnToastInspect;
        Closed += (_, _) =>
        {
            _promptToast?.Close();
            _trayIcon?.Dispose();
            _etw.Dispose();
            _dnsEtw.Dispose();
            _historyDb.Dispose();
            _engineClient?.Dispose();
            _signatures.Dispose();
            _hashCache.SaveIfDirty();
            _scanCts?.Cancel();
            _scanCts?.Dispose();
            _sink.Dispose();
            _dnsSwitch.Dispose();
            _hostsMonitor.Dispose();
            _packetCaptureManager.Dispose();
            _mobileServer?.Dispose();
            _aiDb.Dispose();
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

            AiHistoryGrid.ItemsSource = AiHistory;
            AiAutoInvestigateCheck.IsChecked = _appSettings.Settings.AiAutoInvestigateUnverified;
            AiModelText.Text = _appSettings.Settings.OllamaModel;
            LocalizationManager.CurrentLanguage = _appSettings.Settings.Language;
            SetLanguageComboSelected(_appSettings.Settings.Language);
            LocalizationManager.LanguageChanged += ApplyLocalization;
            ApplyLocalization();
            _ = RefreshAiHistoryAsync();
            _ = CheckOllamaStatusAsync();
            _ = Task.Run(async () =>
            {
                try { await QosRateLimiter.ReapplySavedLimitsAsync(); } catch { }
            });

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
                            if (IsLanClient(row.Client))
                            {
                                TvLanActivityRows.Insert(0, row);
                                while (TvLanActivityRows.Count > 300) TvLanActivityRows.RemoveAt(TvLanActivityRows.Count - 1);
                            }
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
            if (AiTab.IsChecked == true) SyncAiProcessCombo();
            if (TvMobileTab.IsChecked == true && _tickCount % 3 == 0) RefreshTvMobileUi();
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
                            (string.IsNullOrEmpty(r.CallerProgram) ||
                             r.CallerProgram.StartsWith("svchost", StringComparison.OrdinalIgnoreCase) ||
                             r.CallerProgram.StartsWith("(none", StringComparison.OrdinalIgnoreCase)))
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
                existing.UpdateProcessInfo(view.Process);
                if (ReferenceEquals(existing, _inspectedConnectionRow) && ConnectionInspectorPanel.Visibility == Visibility.Visible)
                {
                    ShowConnectionInspector(existing);
                }
                continue;
            }

            IpIntelligenceInfo? remoteIntel = view.Connection.Protocol != Protocol.Udp && view.Connection.Remote?.Address is { } rAddr
                ? _ipIntel.Analyze(rAddr)
                : null;
            var row = new ConnectionRow(view, remoteIntel);
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
                {
                    row.SetSignature(info);
                    if (ReferenceEquals(row, _inspectedConnectionRow) && ConnectionInspectorPanel.Visibility == Visibility.Visible)
                        ShowConnectionInspector(row);
                }

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

    private void OnToastInspect(ProgramSummary s)
    {
        Show();
        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }
        Activate();
        Focus();

        ProgramsTab.IsChecked = true;
        OnViewChanged(this, new RoutedEventArgs());

        if (ProgramsSearchBox != null && !string.IsNullOrEmpty(ProgramsSearchBox.Text))
        {
            ProgramsSearchBox.Text = "";
        }

        var match = Programs.FirstOrDefault(p =>
            string.Equals(p.Key, s.Key, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrEmpty(s.Path) && string.Equals(p.Path, s.Path, StringComparison.OrdinalIgnoreCase)) ||
            string.Equals(p.Name, s.Name, StringComparison.OrdinalIgnoreCase));

        if (match != null)
        {
            ProgramsGrid.SelectedItem = match;
            ProgramsGrid.ScrollIntoView(match);
        }

        StatusText.Text = $"Inspecting {s.Name} — review its details, signature, and connections before deciding.";
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
        if (!IsLoaded) return;
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
        if (!IsLoaded) return;
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
        if (!IsLoaded) return;
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

    // ---- 4-Stage Quarantine & Rollback System ----

    private async void OnQuarantineConnectionProgram(object sender, RoutedEventArgs e)
    {
        var row = SelectedConnection();
        if (row is null || string.IsNullOrWhiteSpace(row.Path)) return;
        await PromptAndQuarantineAsync(row.Path, row.Program);
    }

    private async void OnQuarantineProgram(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is null || string.IsNullOrWhiteSpace(row.Path)) return;
        await PromptAndQuarantineAsync(row.Path, row.Name);
    }

    private async void OnRestoreProgramQuarantine(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is null || string.IsNullOrWhiteSpace(row.Path)) return;
        await PromptAndRestoreQuarantineAsync(row.Path, row.Name);
    }

    private void OnRulesViewQuarantine(object sender, RoutedEventArgs e)
    {
        QuarantineTab.IsChecked = true;
    }

    private async Task PromptAndQuarantineAsync(string path, string name, string reason = "Quarantined by user")
    {
        if (!_isAdmin)
        {
            var res = MessageBox.Show(this,
                $"Administrator privileges are required to perform 5-Stage Active Defense Quarantine on \"{name}\".\n\n" +
                "Quarantine enforces kernel-level execution lockout (IFEO), disables Windows services, and writes system firewall blocks.\n\n" +
                "Would you like to switch to Administrator mode now to complete quarantine?",
                "Administrator Rights Required", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (res == MessageBoxResult.Yes)
            {
                OnSwitchElevationClick(this, new RoutedEventArgs());
            }
            return;
        }

        if (ProtectedPrograms.IsProtected(path))
        {
            MessageBox.Show(this,
                $"Cannot quarantine \"{name}\".\n\nThis executable is a protected Windows operating system component required for system stability.",
                "Protected System Component", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        string selfPath = Environment.ProcessPath ?? "";
        if (!string.IsNullOrEmpty(selfPath) && string.Equals(Path.GetFullPath(path), Path.GetFullPath(selfPath), StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(this, "SpectraNetworkManager cannot quarantine itself.", "Action Refused", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var answer = MessageBox.Show(this,
            $"Perform 5-Stage Active Defense Quarantine on \"{name}\"?\n\n" +
            "This will safely neutralize the program while keeping it 100% reversible:\n" +
            "1. 🛑 Terminate all active process instances & drop active network sockets.\n" +
            "2. ⛔ Enforce kernel-level execution lockout (IFEO) to prevent the program from starting.\n" +
            "3. ⚙️ Identify dedicated Windows services, stop them, and set Startup to Disabled.\n" +
            "4. 🚀 Disable Registry, Startup folder, and Task Scheduler auto-start entries.\n" +
            "5. 🧱 Enforce strict Inbound and Outbound Windows Firewall block rules.\n\n" +
            "A complete snapshot will be saved in the Quarantine Vault for 1-click restore at any time.\n\n" +
            "Proceed with quarantine?",
            $"🛡️ Quarantine: {name}", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes) return;

        try
        {
            StatusText.Text = $"Quarantining {name}...";
            var (success, msg, snapshot) = await _quarantineManager.QuarantineAsync(path, reason);
            if (success && snapshot != null)
            {
                StatusText.Text = $"Quarantined {name}: {snapshot.SummaryDisplay}";
                RefreshQuarantineVault();
                var viewChoice = MessageBox.Show(this,
                    $"\"{name}\" has been successfully quarantined!\n\n" +
                    $"• Execution Lockout: {(snapshot.ExecutionLockoutApplied ? "Enforced (IFEO)" : "Not Set")}\n" +
                    $"• Processes terminated: {snapshot.TerminatedPids.Count}\n" +
                    $"• Sockets closed: {snapshot.ClosedSocketsCount}\n" +
                    $"• Services disabled: {snapshot.ModifiedServices.Count}\n" +
                    $"• Startup entries disabled: {snapshot.DisabledStartupEntries.Count}\n" +
                    $"• Firewall rules applied: {(snapshot.FirewallRulesApplied ? "Inbound + Outbound Block" : "None")}\n\n" +
                    "Would you like to view this item in the Quarantine Vault now?",
                    "Program Quarantined", MessageBoxButton.YesNo, MessageBoxImage.Information);
                if (viewChoice == MessageBoxResult.Yes)
                {
                    QuarantineTab.IsChecked = true;
                }
            }
            else
            {
                MessageBox.Show(this, $"Quarantine failed: {msg}", "Quarantine Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            Error($"Failed to quarantine {name}", ex);
        }

        AfterDecision();
        await RefreshRulesAsync();
        await ForceMonitorRefreshAsync();
    }

    private async Task PromptAndRestoreQuarantineAsync(string path, string name)
    {
        if (!_isAdmin)
        {
            var res = MessageBox.Show(this,
                $"Administrator privileges are required to restore \"{name}\" from quarantine.\n\n" +
                "Restoring requires removing execution lockout (IFEO), modifying Windows services, and restoring firewall rules.\n\n" +
                "Would you like to switch to Administrator mode now to restore this program?",
                "Administrator Rights Required", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (res == MessageBoxResult.Yes)
            {
                OnSwitchElevationClick(this, new RoutedEventArgs());
            }
            return;
        }

        var snapshot = _quarantineVault.FindByPath(path)
            ?? _quarantineVault.GetAll().OrderByDescending(s => s.QuarantinedAtUtc).FirstOrDefault(s => string.Equals(s.ExecutablePath, path, StringComparison.OrdinalIgnoreCase));

        if (snapshot == null)
        {
            Info($"No quarantine snapshot was found in the vault for \"{name}\".\n\nIf this program was blocked normally, use 'Allow' or 'Forget decision' in the Rules tab.");
            return;
        }

        if (snapshot.IsRestored)
        {
            Info($"\"{name}\" has already been restored from quarantine.\n\nExecution lockout, firewall rules, and startup entries are already back to normal.");
            return;
        }

        var answer = MessageBox.Show(this,
            $"Restore \"{name}\" from Quarantine?\n\n" +
            "This will reverse all 5 quarantine actions:\n" +
            "1. ⛔ Remove kernel-level execution lockout (IFEO).\n" +
            "2. 🧱 Remove Inbound/Outbound quarantine firewall block rules.\n" +
            "3. 🚀 Re-enable auto-start registry keys and startup items.\n" +
            "4. ⚙️ Restore Windows Service start types and prompt to restart if needed.\n" +
            "5. 🟢 Restore normal process execution.\n\n" +
            "Proceed with restore?",
            $"🔄 Restore: {name}", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.Yes);

        if (answer != MessageBoxResult.Yes) return;

        try
        {
            StatusText.Text = $"Restoring {name} from quarantine...";
            var (success, msg) = await _quarantineManager.RestoreAsync(snapshot.Id);
            if (success)
            {
                StatusText.Text = $"Restored {name} from quarantine.";
                RefreshQuarantineVault();
                MessageBox.Show(this,
                    $"\"{name}\" has been restored from quarantine.\n\n" +
                    "Execution lockout removed, firewall blocks cleared, services re-enabled, and startup entries restored.",
                    "Restore Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(this, $"Restore failed: {msg}", "Restore Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            Error($"Failed to restore {name}", ex);
        }

        AfterDecision();
        await RefreshRulesAsync();
        await ForceMonitorRefreshAsync();
    }

    // ---- Quarantine Vault Management Handlers ----

    private void RefreshQuarantineVault()
    {
        bool showRestored = QuarantineShowRestoredCheck?.IsChecked == true;
        var all = _quarantineVault.GetAll().OrderByDescending(s => s.QuarantinedAtUtc).ToList();
        var snapshots = showRestored ? all : all.Where(s => !s.IsRestored).ToList();

        QuarantinedItems.Clear();
        foreach (var s in snapshots)
        {
            QuarantinedItems.Add(s);
        }

        int activeCount = all.Count(s => !s.IsRestored);
        QuarantineCountText.Text = $"{activeCount} program{(activeCount != 1 ? "s" : "")} quarantined in vault";

        if (QuarantinedItems.Count > 0)
        {
            if (QuarantineGrid.SelectedItem == null || !QuarantinedItems.Contains((QuarantineSnapshot)QuarantineGrid.SelectedItem))
            {
                QuarantineGrid.SelectedIndex = 0;
            }
        }
        else
        {
            QuarantineGrid.SelectedItem = null;
            ClearQuarantineDetails();
        }
    }

    private void OnQuarantineShowRestoredChanged(object sender, RoutedEventArgs e)
    {
        RefreshQuarantineVault();
    }

    private void ClearQuarantineDetails()
    {
        QuarantineDetailNameText.Text = "No programs quarantined";
        QuarantineDetailReasonText.Text = "The Quarantine Vault is currently empty. To quarantine a suspicious program, right-click any connection or program and select '5-Stage Quarantine', or click 'Quarantine New File...'.";
        QuarantineDetailPathText.Text = "-";
        QuarantineDetailTimestampText.Text = "-";
        QuarantineDetailIdText.Text = "-";
        QuarantineStatusBadgeText.Text = "VAULT EMPTY";
        QuarantineStatusBadge.Background = new SolidColorBrush(Color.FromArgb(0x22, 0x7F, 0x8B, 0xB0));
        QuarantineStatusBadgeText.Foreground = (Brush)FindResource("Muted");
        QuarantineStage1Text.Text = "No active quarantine locks";
        QuarantineStage2Text.Text = "No execution lockouts active";
        QuarantineStage3Text.Text = "No services disabled";
        QuarantineStage4Text.Text = "No auto-start entries disabled";
        QuarantineStage5Text.Text = "No quarantine firewall blocks active";

        if (QuarantineRestoreButton != null)
        {
            QuarantineRestoreButton.IsEnabled = false;
            QuarantineRestoreButton.Content = "🔄 Restore Program (Un-Quarantine)";
        }
        if (QuarantineDetailRestoreButton != null)
        {
            QuarantineDetailRestoreButton.IsEnabled = false;
            QuarantineDetailRestoreButton.Content = "🔄 Restore Program";
        }
    }

    private void OnQuarantineGridSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (QuarantineGrid.SelectedItem is QuarantineSnapshot snap)
        {
            QuarantineDetailNameText.Text = snap.ProgramName;
            QuarantineDetailReasonText.Text = string.IsNullOrWhiteSpace(snap.Reason) ? "Quarantined by user" : snap.Reason;
            QuarantineDetailPathText.Text = snap.ExecutablePath;
            QuarantineDetailTimestampText.Text = snap.QuarantinedAtUtc.ToLocalTime().ToString("f");
            QuarantineDetailIdText.Text = snap.Id;

            if (snap.IsRestored)
            {
                QuarantineStatusBadgeText.Text = "RESTORED";
                QuarantineStatusBadge.Background = new SolidColorBrush(Color.FromArgb(0x33, 0x00, 0xE6, 0x76));
                QuarantineStatusBadgeText.Foreground = new SolidColorBrush(Color.FromRgb(0x00, 0xFF, 0x88));

                if (QuarantineRestoreButton != null)
                {
                    QuarantineRestoreButton.IsEnabled = false;
                    QuarantineRestoreButton.Content = "✔ Already Restored";
                }
                if (QuarantineDetailRestoreButton != null)
                {
                    QuarantineDetailRestoreButton.IsEnabled = false;
                    QuarantineDetailRestoreButton.Content = "✔ Restored";
                }
            }
            else
            {
                QuarantineStatusBadgeText.Text = "QUARANTINED";
                QuarantineStatusBadge.Background = new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0x2B, 0xD6));
                QuarantineStatusBadgeText.Foreground = (Brush)FindResource("Magenta");

                if (QuarantineRestoreButton != null)
                {
                    QuarantineRestoreButton.IsEnabled = true;
                    QuarantineRestoreButton.Content = "🔄 Restore Program (Un-Quarantine)";
                }
                if (QuarantineDetailRestoreButton != null)
                {
                    QuarantineDetailRestoreButton.IsEnabled = true;
                    QuarantineDetailRestoreButton.Content = "🔄 Restore Program";
                }
            }

            QuarantineStage1Text.Text = $"{snap.TerminatedPids.Count} process instance(s) killed | {snap.ClosedSocketsCount} network socket(s) terminated";
            QuarantineStage2Text.Text = snap.ExecutionLockoutApplied
                ? "⛔ ACTIVE: Blocked by Windows Image File Execution Options (IFEO). Program cannot start."
                : (snap.IsRestored ? "✔ Restored: Execution allowed." : "⚪ Not enforced");
            QuarantineStage3Text.Text = snap.ModifiedServices.Count > 0
                ? $"⚙️ {snap.ModifiedServices.Count} Windows service(s) stopped and disabled: {string.Join(", ", snap.ModifiedServices.Select(s => s.ServiceName))}"
                : "⚪ No dedicated Windows services detected";
            QuarantineStage4Text.Text = snap.DisabledStartupEntries.Count > 0
                ? $"🚀 {snap.DisabledStartupEntries.Count} auto-start entry(s) disabled: {string.Join(", ", snap.DisabledStartupEntries.Select(s => s.Name))}"
                : "⚪ No startup registry/folder entries found";
            QuarantineStage5Text.Text = snap.FirewallRulesApplied
                ? "🧱 ACTIVE: Inbound and Outbound Windows Firewall rules blocking all network traffic"
                : (snap.IsRestored ? "✔ Restored: Firewall blocks removed." : "⚪ None");
        }
        else
        {
            ClearQuarantineDetails();
        }
    }

    private void OnRefreshQuarantineVault(object sender, RoutedEventArgs e) => RefreshQuarantineVault();

    private async void OnRestoreQuarantineFromVault(object sender, RoutedEventArgs e)
    {
        if (QuarantineGrid.SelectedItem is QuarantineSnapshot snap)
        {
            if (snap.IsRestored)
            {
                Info($"\"{snap.ProgramName}\" has already been restored from quarantine.\n\nExecution lockout, firewall rules, and startup entries are already back to normal.");
                return;
            }

            await PromptAndRestoreQuarantineAsync(snap.ExecutablePath, snap.ProgramName);
            RefreshQuarantineVault();
        }
        else
        {
            Info("Please select a program in the Quarantine Vault to restore.");
        }
    }

    private async void OnQuarantineBrowseFile(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Executables (*.exe)|*.exe|All Files (*.*)|*.*",
            Title = "Select Executable to Quarantine"
        };
        if (dlg.ShowDialog(this) == true && !string.IsNullOrWhiteSpace(dlg.FileName))
        {
            await PromptAndQuarantineAsync(dlg.FileName, Path.GetFileName(dlg.FileName));
            RefreshQuarantineVault();
        }
    }

    private void OnInvestigateQuarantineAi(object sender, RoutedEventArgs e)
    {
        if (QuarantineGrid.SelectedItem is QuarantineSnapshot snap && !string.IsNullOrWhiteSpace(snap.ExecutablePath))
        {
            _aiSelectedPid = 0;
            _aiSelectedPath = snap.ExecutablePath;
            AiTab.IsChecked = true;
            OnViewChanged(AiTab, new RoutedEventArgs());
            AiTargetDisplay.Text = $"{snap.ProgramName} (Quarantined)";
            AiTargetTitle.Text = snap.ProgramName;
            OnRunAiInvestigationClick(sender, e);
        }
        else
        {
            Info("Please select an item in the Quarantine Vault first.");
        }
    }

    private async void OnRestoreSelectedQuarantine(object sender, RoutedEventArgs e)
    {
        var row = SelectedRule();
        if (row is null || string.IsNullOrWhiteSpace(row.Path)) return;
        await PromptAndRestoreQuarantineAsync(row.Rule.Path, row.Name);
    }

    private void OnDeleteQuarantineSnapshot(object sender, RoutedEventArgs e)
    {
        if (QuarantineGrid.SelectedItem is QuarantineSnapshot snap)
        {
            string msg = snap.IsRestored
                ? $"Remove the history record for \"{snap.ProgramName}\" from the Quarantine Vault?"
                : $"Remove \"{snap.ProgramName}\" from the Quarantine Vault?\n\n⚠️ Warning: This program is currently quarantined. If you remove this record without restoring first, execution lockout and firewall blocks will remain in place.\n\nTo restore execution and network access, click 'Cancel' and select 'Restore Program' instead.\n\nDo you want to permanently delete this snapshot record?";

            if (Confirm(msg, "Remove Vault Record"))
            {
                _quarantineVault.DeleteSnapshot(snap.Id);
                RefreshQuarantineVault();
                StatusText.Text = $"Removed vault record for {snap.ProgramName}";
            }
        }
        else
        {
            Info("Please select an item in the Quarantine Vault to remove.");
        }
    }

    private async void OnPanicRestoreAllQuarantine(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            var res = MessageBox.Show(this,
                "Administrator privileges are required to restore quarantined programs.\n\n" +
                "Would you like to switch to Administrator mode now?",
                "Administrator Rights Required", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (res == MessageBoxResult.Yes)
            {
                OnSwitchElevationClick(this, new RoutedEventArgs());
            }
            return;
        }

        var active = _quarantineVault.GetActive();
        if (active.Count == 0)
        {
            Info("There are no active quarantined programs in the vault.");
            return;
        }

        if (Confirm($"Restore ALL {active.Count} quarantined program(s) and undo all execution locks, service changes, and firewall rules?", "PANIC: Restore All Quarantined"))
        {
            var (count, errors) = await _quarantineManager.RestoreAllActiveAsync();
            RefreshQuarantineVault();
            await RefreshRulesAsync();
            await ForceMonitorRefreshAsync();
            Info($"Successfully restored {count} quarantined program(s)." + (errors.Count > 0 ? $"\n\nWarnings:\n{string.Join("\n", errors)}" : ""));
        }
    }

    private void OnCopyQuarantinePath(object sender, RoutedEventArgs e)
    {
        if (QuarantineGrid.SelectedItem is QuarantineSnapshot snap && !string.IsNullOrWhiteSpace(snap.ExecutablePath))
        {
            System.Windows.Clipboard.SetText(snap.ExecutablePath);
            StatusText.Text = $"Copied path: {snap.ExecutablePath}";
        }
    }

    private void OnOpenQuarantineFolder(object sender, RoutedEventArgs e)
    {
        if (QuarantineGrid.SelectedItem is QuarantineSnapshot snap && !string.IsNullOrWhiteSpace(snap.ExecutablePath))
        {
            try
            {
                if (File.Exists(snap.ExecutablePath))
                {
                    Process.Start("explorer.exe", $"/select,\"{snap.ExecutablePath}\"");
                }
                else
                {
                    string? dir = Path.GetDirectoryName(snap.ExecutablePath);
                    if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                    {
                        Process.Start("explorer.exe", dir);
                    }
                    else
                    {
                        Info($"Directory does not exist: {snap.ExecutablePath}");
                    }
                }
            }
            catch (Exception ex)
            {
                Error("Failed to open file folder", ex);
            }
        }
    }

    // ---- Connection & Process Intelligence Inspector + SHA-256 / VirusTotal / AbuseIPDB / Shodan ----

    private void OnConnectionsGridSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (ConnectionsGrid.SelectedItem is ConnectionRow row)
        {
            ShowConnectionInspector(row);
        }
    }

    private void OnConnectionsGridMouseUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ConnectionsGrid.SelectedItem is ConnectionRow row)
        {
            ShowConnectionInspector(row);
        }
    }

    private void OnCloseConnectionInspector(object sender, RoutedEventArgs e)
    {
        ConnectionInspectorPanel.Visibility = Visibility.Collapsed;
        _inspectedConnectionRow = null;
    }

    private void ShowConnectionInspector(ConnectionRow row)
    {
        if (row == null) return;
        _inspectedConnectionRow = row;

        try
        {
            var identityLevel = ProcessInfo.ClassifyIdentity(row.Path, row.Signature);
            ConnInspectorIdentityText.Text = ProcessInfo.DescribeIdentityLevel(identityLevel, row.Signature).ToUpperInvariant();

            switch (identityLevel)
            {
                case IdentityVerificationLevel.VerifiedSystemBinary:
                case IdentityVerificationLevel.VerifiedPublisherBinary:
                    ConnInspectorIdentityBadge.Background = new SolidColorBrush(Color.FromArgb(0x33, 0x22, 0xE8, 0xFF));
                    ConnInspectorIdentityText.Foreground = (Brush)FindResource("Cyan");
                    break;
                case IdentityVerificationLevel.UnsignedOrUnverified:
                case IdentityVerificationLevel.Unknown:
                    ConnInspectorIdentityBadge.Background = new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0xB0, 0x20));
                    ConnInspectorIdentityText.Foreground = (Brush)FindResource("Amber");
                    break;
                default:
                    ConnInspectorIdentityBadge.Background = new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0x2B, 0xD6));
                    ConnInspectorIdentityText.Foreground = (Brush)FindResource("Magenta");
                    break;
            }

            string startStr = row.StartTimeUtc.HasValue
                ? $"  ·  Started {row.StartTimeUtc.Value.ToLocalTime():HH:mm:ss}"
                : "";
            ConnInspectorProgramText.Text = $"{row.Program} (PID {row.Pid}){startStr}  ·  {row.Signer}";

            var parts = new List<string>();
            if (!string.IsNullOrEmpty(row.ServiceNames))
                parts.Add($"Windows Service: {row.ServiceNames}");
            if (!string.IsNullOrEmpty(row.ParentName))
                parts.Add($"Parent Process: {row.ParentName} (PID {row.ParentPid})");
            ConnInspectorServiceParentText.Text = parts.Count > 0 ? string.Join("   |   ", parts) : "(Standalone process / no hosted service)";

            ConnInspectorCommandLineText.Text = !string.IsNullOrWhiteSpace(row.CommandLine)
                ? row.CommandLine
                : (!string.IsNullOrWhiteSpace(row.Path) ? row.Path : "(Command line unavailable — protected process)");

            string? sha256 = !string.IsNullOrWhiteSpace(row.Path) ? _hashCache.GetSha256(row.Path) : null;
            ConnInspectorSha256Text.Text = !string.IsNullOrEmpty(sha256)
                ? sha256
                : "(Unavailable — system/protected process or no disk path)";

            var intel = row.RemoteIntelInfo;
            ConnInspectorScopeText.Text = (intel?.Category ?? "LOCAL SOCKET").ToUpperInvariant();
            bool isPublic = intel is { IsPublicRoutable: true };
            ConnInspectorScopeBadge.Background = isPublic
                ? new SolidColorBrush(Color.FromArgb(0x33, 0x22, 0xE8, 0xFF))
                : new SolidColorBrush(Color.FromArgb(0x33, 0x8A, 0x9B, 0xB8));
            ConnInspectorScopeText.Foreground = isPublic
                ? (Brush)FindResource("Cyan")
                : (Brush)FindResource("Text");

            ConnInspectorEndpointText.Text = $"{row.Protocol}  {row.Local} ➔ {row.Remote}  [{row.State}]";
            ConnInspectorHostText.Text = !string.IsNullOrWhiteSpace(row.Host) ? row.Host : "(No reverse DNS hostname)";
            ConnInspectorAsnText.Text = intel is not null
                ? $"{intel.CountryName} ({intel.CountryCode})  ·  {intel.Organization}{(string.IsNullOrEmpty(intel.Asn) ? "" : $" ({intel.Asn})")}"
                : "Local Endpoint / Unconnected Socket";
            ConnInspectorPathText.Text = !string.IsNullOrWhiteSpace(row.Path) ? row.Path : "(Kernel or protected process)";

            ConnInspectorAbuseIpBtn.IsEnabled = isPublic;
            ConnInspectorShodanBtn.IsEnabled = isPublic;

            ConnectionInspectorPanel.Visibility = Visibility.Visible;
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"ShowConnectionInspector failed: {ex.Message}");
        }
    }

    private void CheckPathOnVirusTotal(string? path, string displayName)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            Info($"No executable file path is available on disk for \"{displayName}\".\n\nRun SpectraNetworkManager as Administrator if this is an elevated process.");
            return;
        }

        string? sha256 = _hashCache.GetSha256(path);
        if (string.IsNullOrEmpty(sha256))
        {
            Info($"Could not compute SHA-256 hash for:\n{path}");
            return;
        }

        try
        {
            string url = ExecutableHashCache.GetVirusTotalUrl(sha256);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
            StatusText.Text = $"Opened VirusTotal for {displayName} (SHA-256: {sha256[..16]}…).";
        }
        catch (Exception ex)
        {
            Error("Could not open browser for VirusTotal lookup", ex);
        }
    }

    private void CopyPathSha256ToClipboard(string? path, string displayName)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            Info($"No executable file path is available on disk for \"{displayName}\".");
            return;
        }

        string? sha256 = _hashCache.GetSha256(path);
        if (string.IsNullOrEmpty(sha256))
        {
            Info($"Could not compute SHA-256 hash for:\n{path}");
            return;
        }

        try
        {
            System.Windows.Clipboard.SetText(sha256);
            StatusText.Text = $"Copied SHA-256 hash for {displayName} to clipboard: {sha256}";
        }
        catch { }
    }

    private void OnCheckConnectionVirusTotal(object sender, RoutedEventArgs e)
    {
        var row = _inspectedConnectionRow ?? SelectedConnection();
        if (row is not null) CheckPathOnVirusTotal(row.Path, row.Program);
    }

    private void OnCopyConnectionSha256(object sender, RoutedEventArgs e)
    {
        var row = _inspectedConnectionRow ?? SelectedConnection();
        if (row is not null) CopyPathSha256ToClipboard(row.Path, row.Program);
    }

    private void OnCheckConnectionAbuseIpDb(object sender, RoutedEventArgs e)
    {
        var row = _inspectedConnectionRow ?? SelectedConnection();
        if (row?.RemoteAddress is null)
        {
            Info("This entry does not have a remote IP address.");
            return;
        }

        try
        {
            string url = IpIntelligenceService.GetAbuseIpDbUrl(row.RemoteAddress);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
            StatusText.Text = $"Opened AbuseIPDB report for {row.RemoteAddress}.";
        }
        catch (Exception ex)
        {
            Error("Could not open AbuseIPDB in browser", ex);
        }
    }

    private void OnCheckConnectionShodan(object sender, RoutedEventArgs e)
    {
        var row = _inspectedConnectionRow ?? SelectedConnection();
        if (row?.RemoteAddress is null)
        {
            Info("This entry does not have a remote IP address.");
            return;
        }

        try
        {
            string url = IpIntelligenceService.GetShodanUrl(row.RemoteAddress);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
            StatusText.Text = $"Opened Shodan host intelligence for {row.RemoteAddress}.";
        }
        catch (Exception ex)
        {
            Error("Could not open Shodan in browser", ex);
        }
    }

    private void OnCheckProgramVirusTotal(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is not null) CheckPathOnVirusTotal(row.Path, row.Name);
    }

    private void OnCopyProgramSha256(object sender, RoutedEventArgs e)
    {
        var row = SelectedProgram();
        if (row is not null) CopyPathSha256ToClipboard(row.Path, row.Name);
    }

    private void OnCheckStartupVirusTotal(object sender, RoutedEventArgs e)
    {
        var row = SelectedStartupItem();
        if (row is not null) CheckPathOnVirusTotal(row.ExecutablePath, row.Name);
    }

    private void OnCopyStartupSha256(object sender, RoutedEventArgs e)
    {
        var row = SelectedStartupItem();
        if (row is not null) CopyPathSha256ToClipboard(row.ExecutablePath, row.Name);
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
            await _quarantineManager.RestoreAllActiveAsync();
            await BrowserDohGuard.DisableGuardAsync();

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
        BrowserDohGuardBox.IsChecked = BrowserDohGuard.GetStatus().IsEnforced;
        UpdateHostsBannerUi(_hostsMonitor.GetStatus());
        }
        finally
        {
            _isLoadingDnsSettings = false;
        }
    }

    private void OnHostsFileChanged(object? sender, HostsFileStatus status)
    {
        Dispatcher.BeginInvoke(new Action(() => UpdateHostsBannerUi(status)));
    }

    private void UpdateHostsBannerUi(HostsFileStatus status)
    {
        if (!status.IsClean && status.SuspiciousEntries.Count > 0)
        {
            HostsTamperBanner.Visibility = Visibility.Visible;
            string preview = string.Join(", ", status.SuspiciousEntries.Take(3));
            if (status.SuspiciousEntries.Count > 3) preview += $" (+{status.SuspiciousEntries.Count - 3} more)";
            HostsTamperBannerText.Text = $"Attention: Windows hosts file contains {status.SuspiciousEntries.Count} suspicious redirect(s) ({preview})!";

            if (HostsFileStatusBadge != null)
            {
                HostsFileStatusBadge.Text = $"⚠️ Hosts File Guard: {status.SuspiciousEntries.Count} suspicious redirect(s) detected!";
                HostsFileStatusBadge.Foreground = (Brush)FindResource("Magenta");
            }
        }
        else
        {
            HostsTamperBanner.Visibility = Visibility.Collapsed;

            if (HostsFileStatusBadge != null)
            {
                HostsFileStatusBadge.Text = $"🟢 Hosts File Guard: Clean ({status.TotalActiveEntries} active entries, 0 redirects)";
                HostsFileStatusBadge.Foreground = new SolidColorBrush(Color.FromRgb(0x00, 0xFF, 0x88));
            }
        }
    }

    private async void OnRestoreDefaultHosts(object sender, RoutedEventArgs e)
    {
        var answer = MessageBox.Show(this,
            "Are you sure you want to restore the Windows hosts file to clean Microsoft default?\n\n" +
            "A timestamped backup of the current hosts file will be created automatically in your LocalAppData folder.",
            "Restore Clean Hosts File", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        var (success, message) = await _hostsMonitor.RestoreDefaultHostsFileAsync();
        if (success)
        {
            MessageBox.Show(this, message, "Hosts Restored", MessageBoxButton.OK, MessageBoxImage.Information);
            UpdateHostsBannerUi(_hostsMonitor.GetStatus());
        }
        else
        {
            MessageBox.Show(this, message, "Restore Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void OnBrowserDohGuardChanged(object sender, RoutedEventArgs e)
    {
        if (_isLoadingDnsSettings) return;

        bool enable = BrowserDohGuardBox.IsChecked == true;
        try
        {
            if (enable)
            {
                var res = await BrowserDohGuard.EnableGuardAsync();
                StatusText.Text = res.Message;
            }
            else
            {
                var res = await BrowserDohGuard.DisableGuardAsync();
                StatusText.Text = res.Message;
            }
        }
        catch (Exception ex)
        {
            Error("Failed to update Browser DoH Guard policy", ex);
            BrowserDohGuardBox.IsChecked = !enable;
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

    private async Task StartDnsAsync(DnsSettings? explicitSettings = null)
    {
        if (_dnsBusy || _sink.IsRunning) return;
        _dnsBusy = true;
        try
        {
            DnsSettings settings;
            if (explicitSettings != null)
            {
                settings = explicitSettings;
                DnsListenBox.Text = settings.ListenAddress;
                DnsPortBox.Text = settings.Port.ToString(CultureInfo.InvariantCulture);
            }
            else
            {
                if (!TryReadDnsSettings(out var parsed, out string error))
                {
                    Info(error);
                    return;
                }
                settings = parsed;
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
        if (!IsLoaded || _isUpdatingDnsRows) return;
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

            static bool IsValidCallerRow(ConnectionRow c) =>
                c.Pid > 0 && !c.Program.StartsWith("(none", StringComparison.OrdinalIgnoreCase);

            var matchingConn = Rows.FirstOrDefault(c =>
                IsValidCallerRow(c) &&
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
                        IsValidCallerRow(c) &&
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
                    IsValidCallerRow(c) &&
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
                        IsValidCallerRow(c) && (
                            c.Program.StartsWith(rootBase, StringComparison.OrdinalIgnoreCase) ||
                            c.Program.Contains(rootBase, StringComparison.OrdinalIgnoreCase)));
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
            _enforcer.AllowInboundDns(exe, settings.Port, _mobileServer?.Port ?? 8765);
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
                var row = DnsRow.From(recent[i], caller);
                DnsRows.Insert(0, row);
                if (IsLanClient(row.Client))
                {
                    TvLanActivityRows.Insert(0, row);
                    while (TvLanActivityRows.Count > 300) TvLanActivityRows.RemoveAt(TvLanActivityRows.Count - 1);
                }
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
                    if (ReferenceEquals(row, _inspectedConnectionRow) && ConnectionInspectorPanel.Visibility == Visibility.Visible)
                        ShowConnectionInspector(row);
                }

            foreach (var dev in DiscoveredDevices)
            {
                if (dev.Ip != null && dev.Ip.Equals(ip))
                {
                    dev.Hostname = name;
                }
            }

            foreach (var tvRow in TvMobileDevices)
            {
                if (tvRow.Device?.Ip != null && tvRow.Device.Ip.Equals(ip))
                {
                    tvRow.Device.Hostname = name;
                    tvRow.Refresh();
                }
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
            || r.ServiceOrParent.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Local.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Remote.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Host.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.RemoteIntel.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Path.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.CommandLine.Contains(q, StringComparison.OrdinalIgnoreCase)
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

    private bool DnsRowFilter(object item)
    {
        var d = (DnsRow)item;
        string q = DnsCheckBox?.Text.Trim() ?? "";
        if (q.Length == 0) return true;
        return d.Domain.Contains(q, StringComparison.OrdinalIgnoreCase)
            || d.CallerProgram.Contains(q, StringComparison.OrdinalIgnoreCase)
            || d.Client.Contains(q, StringComparison.OrdinalIgnoreCase)
            || d.Type.Contains(q, StringComparison.OrdinalIgnoreCase)
            || d.Result.Contains(q, StringComparison.OrdinalIgnoreCase)
            || d.Detail.Contains(q, StringComparison.OrdinalIgnoreCase)
            || d.Time.Contains(q, StringComparison.OrdinalIgnoreCase);
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

    private void OnDnsFilterChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        if (DnsCheckResult != null)
        {
            DnsCheckResult.Text = "";
        }
        _dnsView.Refresh();
    }

    private void OnClearDnsSearch(object sender, RoutedEventArgs e)
    {
        DnsCheckBox.Text = "";
        DnsCheckResult.Text = "";
        _dnsView.Refresh();
    }

    private async void OnViewChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        ConnectionsPanel.Visibility = ConnectionsTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ProgramsPanel.Visibility = ProgramsTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        StartupPanel.Visibility = StartupTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        TrafficPanel.Visibility = TrafficTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ScannerPanel.Visibility = ScannerTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PacketsPanel.Visibility = PacketsTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        TvMobilePanel.Visibility = TvMobileTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        BrowserGuardPanel.Visibility = BrowserGuardTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        AiPanel.Visibility = AiTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        RulesPanel.Visibility = RulesTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        QuarantinePanel.Visibility = QuarantineTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        StrictPanel.Visibility = StrictTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        DnsPanel.Visibility = DnsTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        BlocksPanel.Visibility = BlocksTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;

        if (TvMobileTab.IsChecked == true) RefreshTvMobileUi();
        if (BrowserGuardTab.IsChecked == true) RefreshBrowserGuardUi();
        if (AiTab.IsChecked == true) RefreshAiUi();
        if (ScannerTab.IsChecked == true) InitScannerTargetSubnet();
        if (StartupTab.IsChecked == true) RefreshStartupItems();
        if (StrictTab.IsChecked == true) UpdateStrictUi();
        if (DnsTab.IsChecked == true) RefreshDnsUi();
        if (RulesTab.IsChecked == true) await RefreshRulesAsync();
        if (QuarantineTab.IsChecked == true) RefreshQuarantineVault();
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
            // Hint appears at most once per program start, and only if the user has not turned it off.
            if (_trayIcon != null && _appSettings.Settings.TrayHintEnabled && TrayHintGate.TryPass())
            {
                _trayIcon.ShowBalloonTip(3000, "SpectraNetworkManager", "SpectraNetworkManager is still running in your system tray. Right-click the tray icon to exit.", System.Windows.Forms.ToolTipIcon.Info);
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

            var trayHintItem = new System.Windows.Forms.ToolStripMenuItem("Show tray hint when closing")
            {
                Checked = _appSettings.Settings.TrayHintEnabled,
                CheckOnClick = true
            };
            trayHintItem.CheckedChanged += (_, _) =>
            {
                Dispatcher.Invoke(() => _appSettings.Save(_appSettings.Settings with { TrayHintEnabled = trayHintItem.Checked }));
            };
            menu.Items.Add(trayHintItem);
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
        if (!IsLoaded) return;
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

    // ---- Port Scanner & Passive LAN Discovery -----------------------------------------------

    private void InitScannerTargetSubnet()
    {
        if (ScannerTargetBox != null && !string.IsNullOrWhiteSpace(ScannerTargetBox.Text)) return;

        try
        {
            var localIp = GetLocalActiveIp();
            if (localIp != null)
            {
                byte[] b = localIp.GetAddressBytes();
                if (ScannerTargetBox != null)
                {
                    ScannerTargetBox.Text = $"{b[0]}.{b[1]}.{b[2]}.0/24";
                }
                if (HudTargetText != null)
                {
                    HudTargetText.Text = $"Target: {b[0]}.{b[1]}.{b[2]}.0/24";
                }
                return;
            }
        }
        catch
        {
        }

        if (ScannerTargetBox != null)
        {
            ScannerTargetBox.Text = "192.168.1.0/24";
        }
        if (HudTargetText != null)
        {
            HudTargetText.Text = "Target: 192.168.1.0/24";
        }
    }

    private void UpdateScannerHud(
        string radarStatus,
        Brush radarBadgeBrush,
        Brush radarTextBrush,
        string targetText,
        string hostsRatio,
        string velocity,
        string eta,
        int devicesCount,
        int portsCount,
        string? activityEvent = null)
    {
        if (HudRadarBadgeText != null) HudRadarBadgeText.Text = radarStatus;
        if (HudRadarBadge != null) HudRadarBadge.Background = radarBadgeBrush;
        if (HudRadarBadgeText != null) HudRadarBadgeText.Foreground = radarTextBrush;
        if (HudTargetText != null) HudTargetText.Text = targetText;
        if (HudHostsRatioText != null) HudHostsRatioText.Text = hostsRatio;
        if (HudVelocityText != null) HudVelocityText.Text = velocity;
        if (HudEtaText != null) HudEtaText.Text = eta;
        if (HudDevicesCountText != null) HudDevicesCountText.Text = devicesCount.ToString();
        if (HudPortsCountText != null) HudPortsCountText.Text = portsCount.ToString();

        if (!string.IsNullOrEmpty(activityEvent) && HudActivityTickerText != null)
        {
            HudActivityTickerText.Text = activityEvent;
        }
    }

    private static IPAddress? GetLocalActiveIp()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback || ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                var ipProps = ni.GetIPProperties();
                if (ipProps.GatewayAddresses.Count == 0) continue;

                foreach (var unicast in ipProps.UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(unicast.Address))
                    {
                        return unicast.Address;
                    }
                }
            }
        }
        catch { }
        return null;
    }

    private static IPAddress? GetDefaultGatewayIp()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback || ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                var ipProps = ni.GetIPProperties();
                foreach (var gw in ipProps.GatewayAddresses)
                {
                    if (gw.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return gw.Address;
                    }
                }
            }
        }
        catch { }
        return null;
    }

    private async void OnStartScan(object sender, RoutedEventArgs e)
    {
        if (_scanCts != null) return;

        string targetText = ScannerTargetBox.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(targetText))
        {
            InitScannerTargetSubnet();
            targetText = ScannerTargetBox.Text?.Trim() ?? "";
        }

        int profileIndex = ScannerProfileCombo.SelectedIndex;

        // Profile 3: Local Machine (All Sockets)
        if (profileIndex == 3)
        {
            try
            {
                ScannerStatusText.Text = "Gathering local listening sockets...";
                var localDev = _localInventory.GetLocalInventory();
                DiscoveredDevices.Clear();
                SelectedDevicePorts.Clear();
                DiscoveredDevices.Add(localDev);
                DevicesGrid.SelectedIndex = 0;
                ScannerStatusText.Text = $"Local machine inventory: {localDev.OpenPorts.Count} listening sockets found.";
                UpdateScannerHud(
                    "💻 LOCAL SOCKETS",
                    new SolidColorBrush(Color.FromArgb(0x33, 0x22, 0xE8, 0xFF)),
                    (Brush)FindResource("Cyan"),
                    "Target: localhost (TCP/UDP)",
                    "1 / 1 Host (100%)",
                    "Instant",
                    "ETA: 0s",
                    1,
                    localDev.OpenPorts.Count,
                    $"[{DateTime.Now:HH:mm:ss}] 💻 Local machine inventory: {localDev.OpenPorts.Count} listening sockets mapped to active processes.");
            }
            catch (Exception ex)
            {
                ScannerStatusText.Text = $"Error reading local sockets: {ex.Message}";
            }
            return;
        }

        // Profile 2: Passive Discovery (Instant)
        if (profileIndex == 2)
        {
            OnPassiveDiscovery(sender, e);
            return;
        }

        // Profiles 0 (Top 20) & 1 (Top 100): Active Port Scan
        List<IPAddress> targets = new();
        try
        {
            if (targetText.Equals("local", StringComparison.OrdinalIgnoreCase) ||
                targetText.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                targetText == "127.0.0.1")
            {
                targets.Add(IPAddress.Loopback);
            }
            else if (targetText.Contains('/'))
            {
                var parts = targetText.Split('/');
                if (IPAddress.TryParse(parts[0], out var baseIp))
                {
                    targets = NetworkScanner.GenerateSubnetIps(baseIp);
                }
                else
                {
                    Warn($"Invalid subnet address format: '{targetText}'. Expected format: 192.168.1.0/24");
                    return;
                }
            }
            else if (IPAddress.TryParse(targetText, out var singleIp))
            {
                targets.Add(singleIp);
            }
            else
            {
                try
                {
                    var addrs = await Dns.GetHostAddressesAsync(targetText);
                    targets.AddRange(addrs.Where(a => a.AddressFamily == AddressFamily.InterNetwork));
                }
                catch
                {
                    Warn($"Could not resolve host '{targetText}'. Please check the hostname or IP address.");
                    return;
                }
            }
        }
        catch (Exception ex)
        {
            Warn($"Failed to parse target: {ex.Message}");
            return;
        }

        if (targets.Count == 0)
        {
            Warn("No valid target IP addresses found to scan.");
            return;
        }

        bool hasExternal = targets.Any(ip => !NetworkScanner.IsPrivateOrLocal(ip));
        if (hasExternal)
        {
            if (!Confirm($"Target '{targetText}' contains public / external Internet IP addresses.\n\nActive scanning external hosts without authorization may trigger network security alerts.\n\nDo you want to proceed with this scan?", "External Network Scan Confirmation"))
            {
                return;
            }
        }

        var portsToScan = profileIndex == 0 ? WellKnownPorts.Top20 : WellKnownPorts.Top100;

        StartScanButton.IsEnabled = false;
        StopScanButton.IsEnabled = true;
        PassiveDiscoverButton.IsEnabled = false;
        ScannerProgressBar.Visibility = Visibility.Visible;
        ScannerProgressBar.Value = 0;
        ScannerStatusText.Text = $"Starting scan of {targets.Count} hosts ({portsToScan.Length} ports each)...";

        DiscoveredDevices.Clear();
        SelectedDevicePorts.Clear();

        UpdateScannerHud(
            "📡 SWEEPING LAN",
            new SolidColorBrush(Color.FromArgb(0x33, 0x22, 0xE8, 0xFF)),
            (Brush)FindResource("Cyan"),
            $"Target: {targetText} ({targets.Count} hosts)",
            $"0 / {targets.Count} Hosts (0%)",
            "0.0 h/s",
            "ETA: calculating...",
            0,
            0,
            $"[{DateTime.Now:HH:mm:ss}] 🚀 Scanner initialized. Probing {targets.Count} hosts across {portsToScan.Length} well-known ports...");

        int totalFoundPorts = 0;
        _scanCts = new CancellationTokenSource();
        var progress = new Progress<ScanProgressReport>(report =>
        {
            if (report.TotalTargets > 0)
            {
                ScannerProgressBar.Value = Math.Min(100, (report.ScannedTargets * 100.0) / report.TotalTargets);
            }
            ScannerStatusText.Text = report.CurrentStatus;

            // Live Stream Newly Discovered Device into the Grid Immediately!
            if (report.NewlyDiscoveredDevice != null)
            {
                var dev = report.NewlyDiscoveredDevice;
                DiscoveredDevices.Add(dev);
                totalFoundPorts += dev.OpenPorts.Count;

                // Select first found device immediately so the inspector card populates live
                if (DevicesGrid.SelectedItem == null)
                {
                    DevicesGrid.SelectedItem = dev;
                }

                try { DevicesGrid.ScrollIntoView(dev); } catch { }

                string portSummary = dev.OpenPorts.Count > 0
                    ? string.Join(", ", dev.OpenPorts.Take(4).Select(p => $"{p.Port}/{p.ServiceName}"))
                    : "Responsive Host";

                HudActivityTickerText.Text = $"[{DateTime.Now:HH:mm:ss}] 🎯 Discovered {dev.IpString} ({dev.KindDisplay}) - {dev.Vendor} - [{portSummary}]";
            }

            string velStr = report.HostsPerSecond > 0 ? $"{report.HostsPerSecond:F1} h/s" : "--";
            string etaStr = report.EstimatedTimeRemaining.HasValue
                ? $"ETA: ~{(int)report.EstimatedTimeRemaining.Value.TotalSeconds}s"
                : "ETA: --";

            HudHostsRatioText.Text = $"{report.ScannedTargets} / {report.TotalTargets} Hosts ({report.ProgressPercentage:F0}%)";
            HudVelocityText.Text = velStr;
            HudEtaText.Text = etaStr;
            HudDevicesCountText.Text = DiscoveredDevices.Count.ToString();
            HudPortsCountText.Text = (report.FoundPorts > 0 ? report.FoundPorts : totalFoundPorts).ToString();

            if (!string.IsNullOrEmpty(report.CurrentProbingIp))
            {
                HudTargetText.Text = $"Probing: {report.CurrentProbingIp}";
            }
        });

        try
        {
            var gateway = GetDefaultGatewayIp();
            var discovered = await _scanner.ScanActiveAsync(
                targets,
                portsToScan,
                timeoutMs: 350,
                maxConcurrency: 35,
                grabBanners: true,
                gatewayIp: gateway,
                progress: progress,
                cancellationToken: _scanCts.Token);

            // In case any were not caught during streaming:
            if (DiscoveredDevices.Count == 0 && discovered.Count > 0)
            {
                foreach (var dev in discovered) DiscoveredDevices.Add(dev);
            }

            if (DevicesGrid.SelectedItem == null && DiscoveredDevices.Count > 0)
            {
                DevicesGrid.SelectedIndex = 0;
            }

            int finalPorts = DiscoveredDevices.Sum(d => d.OpenPorts.Count);
            ScannerStatusText.Text = $"Scan finished. Found {DiscoveredDevices.Count} active devices.";
            UpdateScannerHud(
                "✅ COMPLETE",
                new SolidColorBrush(Color.FromArgb(0x33, 0x00, 0xE6, 0x76)),
                new SolidColorBrush(Color.FromRgb(0x00, 0xFF, 0x88)),
                $"Target: {targetText} (Done)",
                $"{targets.Count} / {targets.Count} Hosts (100%)",
                HudVelocityText.Text,
                "ETA: 0s",
                DiscoveredDevices.Count,
                finalPorts,
                $"[{DateTime.Now:HH:mm:ss}] ✅ Active scan complete: {DiscoveredDevices.Count} devices identified with {finalPorts} open ports.");
        }
        catch (OperationCanceledException)
        {
            int finalPorts = DiscoveredDevices.Sum(d => d.OpenPorts.Count);
            ScannerStatusText.Text = $"Scan stopped by user. Found {DiscoveredDevices.Count} devices.";
            UpdateScannerHud(
                "⏹ STOPPED",
                new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0xB0, 0x20)),
                (Brush)FindResource("Amber"),
                $"Target: {targetText} (Halted)",
                HudHostsRatioText.Text,
                "--",
                "ETA: --",
                DiscoveredDevices.Count,
                finalPorts,
                $"[{DateTime.Now:HH:mm:ss}] ⏹ User halted scan. Preserved {DiscoveredDevices.Count} discovered devices in grid.");
        }
        catch (Exception ex)
        {
            ScannerStatusText.Text = $"Scan error: {ex.Message}";
        }
        finally
        {
            StartScanButton.IsEnabled = true;
            StopScanButton.IsEnabled = false;
            PassiveDiscoverButton.IsEnabled = true;
            ScannerProgressBar.Visibility = Visibility.Collapsed;
            _scanCts?.Dispose();
            _scanCts = null;
        }
    }

    private void OnStopScan(object sender, RoutedEventArgs e)
    {
        if (_scanCts != null)
        {
            _scanCts.Cancel();
            StopScanButton.IsEnabled = false;
            ScannerStatusText.Text = "Stopping scan...";
            if (HudRadarBadgeText != null) HudRadarBadgeText.Text = "STOPPING...";
        }
    }

    private void OnPassiveDiscovery(object sender, RoutedEventArgs e)
    {
        try
        {
            ScannerStatusText.Text = "Reading local ARP neighbor cache & DNS client activity...";
            var localIp = GetLocalActiveIp();
            var gatewayIp = GetDefaultGatewayIp();

            var dnsStats = _sink.Activity.Snapshot();
            var knownClients = dnsStats.TopClients.Select(c => c.Key).ToList();

            var discovered = _scanner.DiscoverPassive(knownClients, localIp, gatewayIp);

            DiscoveredDevices.Clear();
            SelectedDevicePorts.Clear();

            foreach (var dev in discovered)
            {
                DiscoveredDevices.Add(dev);
            }

            if (DiscoveredDevices.Count > 0)
            {
                DevicesGrid.SelectedIndex = 0;
            }

            int finalPorts = discovered.Sum(d => d.OpenPorts.Count);
            ScannerStatusText.Text = $"Passive discovery found {discovered.Count} devices in ARP table (0 probe packets sent).";
            UpdateScannerHud(
                "⚡ PASSIVE SNAPSHOT",
                new SolidColorBrush(Color.FromArgb(0x33, 0x22, 0xE8, 0xFF)),
                (Brush)FindResource("Cyan"),
                "Source: ARP & Neighbor Cache",
                $"{discovered.Count} Cached Hosts",
                "Instant",
                "ETA: 0s",
                discovered.Count,
                finalPorts,
                $"[{DateTime.Now:HH:mm:ss}] ⚡ Passive discovery snapshot loaded {discovered.Count} LAN neighbors instantly with zero network packets emitted.");
        }
        catch (Exception ex)
        {
            ScannerStatusText.Text = $"Passive discovery error: {ex.Message}";
        }
    }

    private void OnDevicesGridSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (DevicesGrid.SelectedItem is DiscoveredDevice dev)
        {
            DeviceTypeBadgeText.Text = dev.KindDisplay.ToUpperInvariant();
            DeviceTypeBadge.Background = dev.Kind switch
            {
                DeviceKind.SmartTv => new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0x2B, 0xD6)),
                DeviceKind.MobileOrTablet => new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0xAA, 0x00)),
                DeviceKind.RouterOrGateway => new SolidColorBrush(Color.FromArgb(0x33, 0x22, 0xE8, 0xFF)),
                DeviceKind.Workstation => new SolidColorBrush(Color.FromArgb(0x33, 0x22, 0xE8, 0xFF)),
                _ => new SolidColorBrush(Color.FromArgb(0x33, 0x8A, 0x9B, 0xB8))
            };
            DeviceTypeBadgeText.Foreground = dev.Kind switch
            {
                DeviceKind.SmartTv => (Brush)FindResource("Magenta"),
                DeviceKind.MobileOrTablet => (Brush)FindResource("Amber"),
                DeviceKind.RouterOrGateway => (Brush)FindResource("Cyan"),
                _ => (Brush)FindResource("Text")
            };

            InspectorDeviceNameText.Text = !string.IsNullOrEmpty(dev.Hostname)
                ? dev.Hostname
                : (!string.IsNullOrEmpty(dev.Vendor) ? $"{dev.Vendor} ({dev.IpString})" : dev.IpString);
            InspectorDeviceDescText.Text = $"{dev.DeviceDescription}  ·  Vendor: {dev.Vendor}";
            InspectorDeviceIpText.Text = dev.IpString;
            InspectorDeviceMacText.Text = !string.IsNullOrEmpty(dev.MacAddress) ? dev.MacAddress : "(No MAC / Virtual)";
            InspectorDeviceHostText.Text = !string.IsNullOrEmpty(dev.Hostname) ? dev.Hostname : "(None resolved)";
            InspectorDeviceReasonText.Text = !string.IsNullOrEmpty(dev.DeviceDescription) ? dev.DeviceDescription : dev.KindDisplay;

            SelectedDevicePorts.Clear();
            foreach (var port in dev.OpenPorts)
            {
                SelectedDevicePorts.Add(port);
            }
        }
        else
        {
            DeviceTypeBadgeText.Text = "DEVICE";
            DeviceTypeBadge.Background = new SolidColorBrush(Color.FromArgb(0x33, 0x22, 0xE8, 0xFF));
            DeviceTypeBadgeText.Foreground = (Brush)FindResource("Cyan");
            InspectorDeviceNameText.Text = "Select a device to inspect";
            InspectorDeviceDescText.Text = "";
            InspectorDeviceIpText.Text = "-";
            InspectorDeviceMacText.Text = "-";
            InspectorDeviceHostText.Text = "-";
            InspectorDeviceReasonText.Text = "-";
            SelectedDevicePorts.Clear();
        }
    }

    private async void OnProtectDeviceWithDns(object sender, RoutedEventArgs e)
    {
        var dev = DevicesGrid.SelectedItem as DiscoveredDevice;
        if (dev == null)
        {
            Info("Please select a device in the list to protect with DNS Sinkhole.");
            return;
        }

        var localIp = GetLocalActiveIp();
        string localIpStr = localIp?.ToString() ?? "your PC's LAN IP";

        if (_sink.Settings.ListenAddress == "127.0.0.1")
        {
            if (Confirm(
                $"To protect LAN devices (such as Smart TVs, Mobile phones, or Game Consoles), Spectra's DNS Sinkhole needs to listen on all interfaces (0.0.0.0) instead of 127.0.0.1.\n\nWould you like Spectra to enable LAN listening on 0.0.0.0 and start protecting device '{dev.Hostname ?? dev.IpString}'?",
                "Enable LAN DNS Protection"))
            {
                _sink.Settings.ListenAddress = "0.0.0.0";
                _sink.SaveSettingsOnly(_sink.Settings);
                string exe = Environment.ProcessPath ?? "";
                _enforcer.AllowInboundDns(exe, _sink.Settings.Port, _mobileServer?.Port ?? 8765);
                if (_sink.IsRunning)
                {
                    _sink.Stop();
                    await StartDnsAsync();
                }
            }
            else
            {
                return;
            }
        }

        dev.ProtectionStatus = "Protected (DNS Active)";
        DevicesGrid.Items.Refresh();

        Info(
            $"Device '{dev.Hostname ?? dev.IpString}' ({dev.IpString}) is configured for Spectra DNS Protection!\n\n" +
            $"To activate ad-blocking and privacy filtering on this {dev.KindDisplay}:\n" +
            $"1. Open Wi-Fi / Network Settings on your {dev.KindDisplay}.\n" +
            $"2. Set DNS Server to: {localIpStr}\n\n" +
            "All telemetry, smart TV ads, and trackers will be blocked automatically!");
    }

    private void OnRescanSelectedHost(object sender, RoutedEventArgs e)
    {
        if (DevicesGrid.SelectedItem is DiscoveredDevice dev)
        {
            ScannerTargetBox.Text = dev.IpString;
            ScannerProfileCombo.SelectedIndex = 1; // Top 100
            OnStartScan(sender, e);
        }
    }

    private void OnOpenDeviceInBrowser(object sender, RoutedEventArgs e)
    {
        if (DevicesGrid.SelectedItem is DiscoveredDevice dev)
        {
            bool hasHttps = dev.OpenPorts.Any(p => p.Port == 443 || p.Port == 8443);
            string scheme = hasHttps ? "https" : "http";
            string url = $"{scheme}://{dev.IpString}";
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                Warn($"Failed to open web browser for {url}: {ex.Message}");
            }
        }
    }

    private void OnCopyDeviceIp(object sender, RoutedEventArgs e)
    {
        if (DevicesGrid.SelectedItem is DiscoveredDevice dev)
        {
            try
            {
                System.Windows.Clipboard.SetText(dev.IpString);
                StatusText.Text = $"Copied IP address: {dev.IpString}";
            }
            catch { }
        }
    }

    private void OnCopyDeviceMac(object sender, RoutedEventArgs e)
    {
        if (DevicesGrid.SelectedItem is DiscoveredDevice dev && !string.IsNullOrEmpty(dev.MacAddress))
        {
            try
            {
                System.Windows.Clipboard.SetText(dev.MacAddress);
                StatusText.Text = $"Copied MAC address: {dev.MacAddress}";
            }
            catch { }
        }
    }

    private void OnExportScannerCsv(object sender, RoutedEventArgs e)
    {
        if (DiscoveredDevices.Count == 0)
        {
            Info("No discovered devices to export. Run a scan or passive discovery first.");
            return;
        }

        try
        {
            var sfd = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"spectranetworkmanager-devices-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
                DefaultExt = ".csv",
                Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
            };
            if (sfd.ShowDialog(this) == true)
            {
                using var writer = new StreamWriter(sfd.FileName, append: false, Encoding.UTF8);
                NetworkScanner.ExportToCsv(DiscoveredDevices, writer);
                StatusText.Text = $"Exported {DiscoveredDevices.Count} devices to CSV.";
            }
        }
        catch (Exception ex)
        {
            Warn($"Failed to export devices to CSV: {ex.Message}");
        }
    }

    private void OnExportScannerJson(object sender, RoutedEventArgs e)
    {
        if (DiscoveredDevices.Count == 0)
        {
            Info("No discovered devices to export. Run a scan or passive discovery first.");
            return;
        }

        try
        {
            var sfd = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"spectranetworkmanager-devices-{DateTime.Now:yyyyMMdd-HHmmss}.json",
                DefaultExt = ".json",
                Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
            };
            if (sfd.ShowDialog(this) == true)
            {
                using var writer = new StreamWriter(sfd.FileName, append: false, Encoding.UTF8);
                NetworkScanner.ExportToJson(DiscoveredDevices, writer);
                StatusText.Text = $"Exported {DiscoveredDevices.Count} devices to JSON.";
            }
        }
        catch (Exception ex)
        {
            Warn($"Failed to export devices to JSON: {ex.Message}");
        }
    }

    // ---- Packet Inspector & Protocol Dissector Engine ----

    private void InitPacketCaptureInterfaces()
    {
        CaptureInterfaceCombo.Items.Clear();
        CaptureInterfaceCombo.Items.Add("Default / Primary Interface");

        try
        {
            var ips = WindowsRawSocketCaptureProvider.GetAllActiveIPv4Addresses();
            foreach (var ip in ips)
            {
                CaptureInterfaceCombo.Items.Add(ip.ToString());
            }
        }
        catch { }

        CaptureInterfaceCombo.SelectedIndex = 0;
    }

    private (int? Pid, string? Name) MatchConnectionToProcess(IPAddress srcIp, int srcPort, IPAddress dstIp, int dstPort, Protocol proto)
    {
        var conns = _lastConnections;
        for (int i = 0; i < conns.Count; i++)
        {
            var c = conns[i].Connection;
            if (c.Protocol == proto)
            {
                if (c.Local?.Port == srcPort || c.Local?.Port == dstPort)
                {
                    return (c.ProcessId, conns[i].Process.Name);
                }
            }
        }
        return (null, null);
    }

    private void OnPacketBatchFlushed(IReadOnlyList<CapturedPacket> batch, PacketCaptureStats stats)
    {
        Dispatcher.BeginInvoke(new Action(() =>
        {
            PacketStatsText.Text = $"Buffer: {stats.BufferCount:N0} / {stats.BufferCapacity:N0} | {stats.PacketsPerSecond:F1} pkt/s | Total: {stats.TotalPackets:N0} pkts ({stats.TotalBytes / 1024.0 / 1024.0:F1} MB) | Provider: {stats.ActiveProvider}";

            if (batch.Count > 0)
            {
                foreach (var p in batch)
                {
                    CapturedPackets.Add(new PacketRow(p));
                }

                while (CapturedPackets.Count > 1000)
                {
                    CapturedPackets.RemoveAt(0);
                }
            }
        }));
    }

    private void OnPacketStatusChanged(string message)
    {
        Dispatcher.BeginInvoke(new Action(() =>
        {
            StatusText.Text = message;
        }));
    }

    private bool PacketRowFilter(object item)
    {
        if (item is not PacketRow row) return false;
        var p = row.Packet;

        if (!string.IsNullOrEmpty(_packetProtocolFilter) && !string.Equals(_packetProtocolFilter, "ALL", StringComparison.OrdinalIgnoreCase))
        {
            if (_packetProtocolFilter.Equals("TLS", StringComparison.OrdinalIgnoreCase) && p.Protocol != PacketProtocol.Tls) return false;
            if (_packetProtocolFilter.Equals("DNS", StringComparison.OrdinalIgnoreCase) && p.Protocol != PacketProtocol.Dns) return false;
            if (_packetProtocolFilter.Equals("HTTP", StringComparison.OrdinalIgnoreCase) && p.Protocol != PacketProtocol.Http) return false;
            if (_packetProtocolFilter.Equals("TCP", StringComparison.OrdinalIgnoreCase) && p.Protocol != PacketProtocol.Tcp && p.Protocol != PacketProtocol.Tls && p.Protocol != PacketProtocol.Http) return false;
            if (_packetProtocolFilter.Equals("UDP", StringComparison.OrdinalIgnoreCase) && p.Protocol != PacketProtocol.Udp && p.Protocol != PacketProtocol.Dns) return false;
        }

        if (!string.IsNullOrWhiteSpace(_packetSearchTerm))
        {
            bool matches = (p.HostOrSni?.Contains(_packetSearchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
                           || p.SourceAddress.ToString().Contains(_packetSearchTerm, StringComparison.OrdinalIgnoreCase)
                           || p.DestinationAddress.ToString().Contains(_packetSearchTerm, StringComparison.OrdinalIgnoreCase)
                           || p.SourcePort.ToString(CultureInfo.InvariantCulture).Contains(_packetSearchTerm)
                           || p.DestinationPort.ToString(CultureInfo.InvariantCulture).Contains(_packetSearchTerm)
                           || (p.ProcessName?.Contains(_packetSearchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
                           || p.Info.Contains(_packetSearchTerm, StringComparison.OrdinalIgnoreCase);

            if (!matches) return false;
        }

        return true;
    }

    private async void OnStartCapture(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            Info("Packet inspection requires Administrator privileges to bind network sockets.\n\nPlease restart SpectraNetworkManager with 'Run as administrator'.");
            return;
        }

        string? selectedIp = null;
        if (CaptureInterfaceCombo.SelectedIndex > 0 && CaptureInterfaceCombo.SelectedItem is string ipStr)
        {
            selectedIp = ipStr;
        }

        StartCaptureButton.IsEnabled = false;
        StopCaptureButton.IsEnabled = true;
        StatusText.Text = "Starting native packet capture...";

        bool ok = await _packetCaptureManager.StartAsync(selectedIp);
        if (!ok)
        {
            StartCaptureButton.IsEnabled = true;
            StopCaptureButton.IsEnabled = false;
        }
    }

    private async void OnStopCapture(object sender, RoutedEventArgs e)
    {
        StartCaptureButton.IsEnabled = true;
        StopCaptureButton.IsEnabled = false;
        await _packetCaptureManager.StopAsync();
    }

    private async void OnCaptureInterfaceChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (_packetCaptureManager?.IsRunning == true)
        {
            await _packetCaptureManager.StopAsync();
            string? ip = CaptureInterfaceCombo.SelectedIndex > 0 ? CaptureInterfaceCombo.SelectedItem as string : null;
            await _packetCaptureManager.StartAsync(ip);
        }
    }

    private void OnPacketFilterChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (PacketProtocolFilterCombo.SelectedItem is ComboBoxItem item)
        {
            string content = item.Content?.ToString() ?? "All Traffic";
            _packetProtocolFilter = content switch
            {
                "TLS (HTTPS)" => "TLS",
                "DNS" => "DNS",
                "HTTP" => "HTTP",
                "TCP" => "TCP",
                "UDP" => "UDP",
                _ => "ALL"
            };
            CapturedPacketsView?.Refresh();
        }
    }

    private void OnPacketSearchChanged(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded) return;
        _packetSearchTerm = PacketSearchBox.Text.Trim();
        CapturedPacketsView?.Refresh();
    }

    private void OnClearPackets(object sender, RoutedEventArgs e)
    {
        _packetCaptureManager.Clear();
        CapturedPackets.Clear();
        PacketInspectorDetailsText.Text = "Select a packet in the table above to view dissected protocol headers and decoded metadata.";
        PacketHexBox.Text = "Hex stream preview will appear here.";
    }

    private void OnPacketsGridSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (PacketsGrid.SelectedItem is PacketRow row)
        {
            ShowPacketInspector(row.Packet);
        }
    }

    private void ShowPacketInspector(CapturedPacket p)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"FRAME #{p.Id} DETAILS:");
        sb.AppendLine($"  Timestamp (UTC): {p.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
        sb.AppendLine($"  Direction:       {p.DirectionDisplay}");
        sb.AppendLine($"  Total Wire Size: {p.TotalLength} bytes");
        sb.AppendLine();
        sb.AppendLine("NETWORK LAYER (L3):");
        sb.AppendLine($"  Source:          {p.SourceAddress}");
        sb.AppendLine($"  Destination:     {p.DestinationAddress}");
        sb.AppendLine();
        sb.AppendLine("TRANSPORT LAYER (L4):");
        sb.AppendLine($"  Protocol:        {p.ProtocolDisplay}");
        sb.AppendLine($"  Source Port:     {p.SourcePort}");
        sb.AppendLine($"  Dest Port:       {p.DestinationPort}");
        if (!string.IsNullOrEmpty(p.TcpFlags))
        {
            sb.AppendLine($"  TCP Flags:       {p.TcpFlags}");
        }
        sb.AppendLine($"  Payload Length:  {p.PayloadLength} bytes");
        sb.AppendLine();
        sb.AppendLine("APPLICATION / PROTOCOL DISSECTION:");
        if (!string.IsNullOrEmpty(p.HostOrSni))
        {
            string hostLabel = p.Protocol == PacketProtocol.Tls ? "TLS SNI Hostname" : (p.Protocol == PacketProtocol.Dns ? "DNS Queried Name" : "HTTP Host Header");
            sb.AppendLine($"  {hostLabel}: {p.HostOrSni}");
        }
        sb.AppendLine($"  Protocol Summary: {p.Info}");
        sb.AppendLine();
        sb.AppendLine("PROCESS CORRELATION:");
        sb.AppendLine($"  Owning Process:  {p.ProcessDisplay}");

        PacketInspectorDetailsText.Text = sb.ToString();
        PacketHexBox.Text = p.HexDumpPreview;
    }

    private async void OnExportPcapng(object sender, RoutedEventArgs e)
    {
        var stats = _packetCaptureManager.GetStats();
        if (stats.BufferCount == 0)
        {
            Info("No packets in the buffer to export. Start packet capture first.");
            return;
        }

        try
        {
            var sfd = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"SpectraNetworkManager-Capture-{DateTime.Now:yyyyMMdd-HHmmss}.pcapng",
                DefaultExt = ".pcapng",
                Filter = "Wireshark PCAPNG files (*.pcapng)|*.pcapng|All files (*.*)|*.*"
            };
            if (sfd.ShowDialog(this) == true)
            {
                StatusText.Text = "Exporting PCAPNG capture...";
                await _packetCaptureManager.ExportPcapngAsync(sfd.FileName);
                StatusText.Text = $"Exported {stats.BufferCount} packets to {Path.GetFileName(sfd.FileName)}.";
                Info($"Successfully exported {stats.BufferCount:N0} packets to:\n\n{sfd.FileName}\n\nThis file can be opened directly in Wireshark, TShark, or Network Monitor.");
            }
        }
        catch (Exception ex)
        {
            Warn($"Failed to export PCAPNG file: {ex.Message}");
        }
    }

    private async void OnExportPacketsCsv(object sender, RoutedEventArgs e)
    {
        var stats = _packetCaptureManager.GetStats();
        if (stats.BufferCount == 0)
        {
            Info("No packets in the buffer to export. Start packet capture first.");
            return;
        }

        try
        {
            var sfd = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"SpectraNetworkManager-Packets-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
                DefaultExt = ".csv",
                Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
            };
            if (sfd.ShowDialog(this) == true)
            {
                StatusText.Text = "Exporting packet table to CSV...";
                await _packetCaptureManager.ExportCsvAsync(sfd.FileName);
                StatusText.Text = $"Exported {stats.BufferCount} packets to {Path.GetFileName(sfd.FileName)}.";
            }
        }
        catch (Exception ex)
        {
            Warn($"Failed to export CSV file: {ex.Message}");
        }
    }

    private void OnCopyPacketHost(object sender, RoutedEventArgs e)
    {
        if (PacketsGrid.SelectedItem is PacketRow row && !string.IsNullOrEmpty(row.HostOrSni))
        {
            System.Windows.Clipboard.SetText(row.HostOrSni);
            StatusText.Text = $"Copied host to clipboard: {row.HostOrSni}";
        }
    }

    private void OnCopyPacketSource(object sender, RoutedEventArgs e)
    {
        if (PacketsGrid.SelectedItem is PacketRow row)
        {
            System.Windows.Clipboard.SetText(row.SourceEndpointDisplay);
            StatusText.Text = $"Copied source address: {row.SourceEndpointDisplay}";
        }
    }

    private void OnCopyPacketDestination(object sender, RoutedEventArgs e)
    {
        if (PacketsGrid.SelectedItem is PacketRow row)
        {
            System.Windows.Clipboard.SetText(row.DestinationEndpointDisplay);
            StatusText.Text = $"Copied destination address: {row.DestinationEndpointDisplay}";
        }
    }

    private async void OnBlockPacketHostInDns(object sender, RoutedEventArgs e)
    {
        if (PacketsGrid.SelectedItem is PacketRow row && !string.IsNullOrEmpty(row.HostOrSni))
        {
            try
            {
                await _sink.BlockDomainAsync(row.HostOrSni);
                LoadDnsSettingsIntoUi();
                StatusText.Text = $"{row.HostOrSni} is always blocked in DNS now.";
            }
            catch (Exception ex)
            {
                Error("Could not add DNS block rule", ex);
            }
        }
    }

    private void OnBlockPacketRemoteInFirewall(object sender, RoutedEventArgs e)
    {
        if (PacketsGrid.SelectedItem is PacketRow row)
        {
            var targetIp = row.Packet.IsInbound ? row.Packet.SourceAddress : row.Packet.DestinationAddress;
            if (targetIp != null && !IPAddress.IsLoopback(targetIp))
            {
                var answer = MessageBox.Show(this,
                    $"Block all incoming & outgoing network traffic to remote IP \"{targetIp}\" in Windows Firewall?",
                    "Block Remote IP", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
                if (answer == MessageBoxResult.Yes)
                {
                    try
                    {
                        var plan = RulePlanner.Plan(RuleDirection.Both, new TrafficScope(Addresses: targetIp.ToString()));
                        _enforcer.Block($"IP-Block-{targetIp}", plan, $"Manual Packet Block {targetIp}");
                        StatusText.Text = $"Blocked remote IP: {targetIp}";
                    }
                    catch (Exception ex)
                    {
                        Error($"Failed to block IP {targetIp}", ex);
                    }
                }
            }
        }
    }

    // ---- TV & Mobile Protection Hub & Browser Guard --------------------------

    private void InitTvMobileAndBrowserGuardUi()
    {
        GuardResourceTypeCombo.ItemsSource = new[] { "All Types", "Media / Video", "Sub-frame (iFrame)", "Script", "XHR / Fetch" };
        GuardResourceTypeCombo.SelectedIndex = 0;

        TvGroupAssignCombo.ItemsSource = new[] { TvMobileManager.SmartTvsGroupName, TvMobileManager.MobileDevicesGroupName, "Default" };
        TvGroupAssignCombo.SelectedIndex = 0;

        _mobileServer = new MobileCompanionServer(8765)
        {
            GetMetrics = () =>
            {
                var stats = _sink.Activity.Snapshot();
                int activeClients = TvMobileDevices.Count(r => r.Device != null);
                return (_sink.IsRunning, stats.Total, stats.Blocked, stats.BlockedPercent, activeClients);
            },
            GetRecentQueries = () =>
            {
                return Dispatcher.Invoke(() => DnsRows.Take(25).Select(r => new { domain = r.Domain, isBlocked = r.IsBlocked }).ToList());
            },
            GetDevices = () =>
            {
                return Dispatcher.Invoke(() => TvMobileDevices.Select(r => new
                {
                    name = r.Hostname,
                    ip = r.IpString,
                    type = r.DeviceTypeDisplay,
                    status = r.ProtectionBadge
                }).ToList());
            },
            PauseDnsAction = (mins) =>
            {
                Dispatcher.Invoke(() =>
                {
                    _sink.Settings.ClientGroups.ForEach(g => g.BlockingEnabled = false);
                    _sink.SaveSettingsOnly(_sink.Settings);
                    StatusText.Text = $"DNS Sinkhole paused for {mins} minutes from mobile companion.";
                });
            },
            ResumeDnsAction = () =>
            {
                Dispatcher.Invoke(() =>
                {
                    _sink.Settings.ClientGroups.ForEach(g => g.BlockingEnabled = true);
                    _sink.SaveSettingsOnly(_sink.Settings);
                    StatusText.Text = "DNS Sinkhole protection resumed from mobile companion.";
                });
            }
        };

        _mobileServer.RemoteContactReceived += (remoteIp, path) =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                var row = new DnsRow(
                    DateTime.Now.ToString("HH:mm:ss"),
                    remoteIp,
                    $"Mobile Companion ({path})",
                    "HTTP",
                    "✅ CONTACT",
                    "Remote device reached companion page",
                    0,
                    false,
                    false,
                    null!);
                TvLanActivityRows.Insert(0, row);
                while (TvLanActivityRows.Count > 300) TvLanActivityRows.RemoveAt(TvLanActivityRows.Count - 1);
                if (TvSubTabDiagnostics?.IsChecked == true) RefreshTvDiagnosticsUi();
            });
        };

        RefreshBrowserGuardUi();
    }

    private void RefreshTvMobileUi()
    {
        TvMobileManager.EnsureDefaultGroups(_sink.Settings);

        // LAN protection banner + toggle button (state comes from what is really bound, not from settings)
        ApplyLanBanner();
        QueueLanProbeIfStale();

        // Detect Gateway IP
        IPAddress? gatewayIp = null;
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (var g in ni.GetIPProperties().GatewayAddresses)
                    {
                        if (g.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            gatewayIp = g.Address;
                            break;
                        }
                    }
                    if (gatewayIp != null) break;
                }
            }
        }
        catch { }

        // Populate LAN devices from neighbor scanner if empty
        var neighbors = _neighborScanner.GetNeighborTable();
        var knownDevices = new Dictionary<string, DiscoveredDevice>(StringComparer.OrdinalIgnoreCase);

        foreach (var dev in DiscoveredDevices)
        {
            if (dev.Ip != null && !IPAddress.IsLoopback(dev.Ip) && !dev.Ip.Equals(IPAddress.None) && !dev.Ip.Equals(IPAddress.Broadcast))
            {
                byte[] b = dev.Ip.GetAddressBytes();
                if (b.Length != 4 || (b[0] < 224 && b[0] != 0 && b[3] != 255))
                    knownDevices[dev.Ip.ToString()] = dev;
            }
        }

        foreach (var n in neighbors)
        {
            if (n.Ip != null && !knownDevices.ContainsKey(n.Ip.ToString()))
            {
                byte[] b = n.Ip.GetAddressBytes();
                if (b.Length == 4 && (b[0] >= 224 || b[0] == 0 || b[3] == 255))
                    continue;

                string? host = _dns.Request(n.Ip);
                var classification = DeviceClassifier.Classify(n.Mac, host ?? "", null, n.IsGateway);
                var dev = new DiscoveredDevice
                {
                    Ip = n.Ip,
                    MacAddress = n.Mac,
                    Vendor = classification.Vendor,
                    Hostname = host ?? "",
                    Kind = classification.Kind,
                    DeviceDescription = classification.Description,
                    IsGateway = n.IsGateway,
                    FirstSeen = DateTimeOffset.UtcNow,
                    LastSeen = DateTimeOffset.UtcNow
                };
                knownDevices[n.Ip.ToString()] = dev;
            }
        }

        // Check if queries from gateway IP are seen
        bool gatewayForwardingDetected = false;
        if (gatewayIp != null)
        {
            int gwQueryCount = DnsRows.Count(r => DnsClientMatch.IsSameClient(r.Client, gatewayIp.ToString()));
            if (gwQueryCount > 5)
            {
                gatewayForwardingDetected = true;
                TvGatewayNoticeBanner.Visibility = Visibility.Visible;
                TvGatewayNoticeText.Text = $" (Gateway: {gatewayIp})";
            }
            else
            {
                TvGatewayNoticeBanner.Visibility = Visibility.Collapsed;
            }
        }

        string? selectedDeviceIp = (TvMobileGrid.SelectedItem as TvMobileDeviceRow)?.IpString;
        TvMobileDevices.Clear();
        int directCount = 0;
        int gwCount = 0;
        int bypassCount = 0;

        foreach (var kvp in knownDevices)
        {
            var dev = kvp.Value;
            string ipStr = dev.IpString;

            // Query stats for this device IP
            var matchingQueries = DnsRows.Where(r => DnsClientMatch.IsSameClient(r.Client, ipStr)).ToList();
            int totalQ = matchingQueries.Count;
            int blockedQ = matchingQueries.Count(q => q.IsBlocked);
            DateTime? lastSeen = matchingQueries.Count > 0 ? matchingQueries.Max(q => q.Entry.Time).UtcDateTime : null;
            bool dohAttempt = matchingQueries.Any(q => q.Domain.Contains("cloudflare-dns") || q.Domain.Contains("dns.google") || q.Domain.Contains("quad9"));

            var info = DeviceProtectionEvaluator.Evaluate(dev.Ip, gatewayForwardingDetected ? gatewayIp : null, lastSeen, totalQ, blockedQ, dohAttempt);

            switch (info.Level)
            {
                case ProtectionLevel.DirectProtected: directCount++; break;
                case ProtectionLevel.GatewayRouted: gwCount++; break;
                default: bypassCount++; break;
            }

            // Find assigned group in DNS settings
            string assignedGroup = "Default";
            var grp = _sink.Settings.ClientGroups.FirstOrDefault(g => g.ClientRanges.Any(r => r.Trim().Equals(ipStr, StringComparison.OrdinalIgnoreCase)));
            if (grp != null) assignedGroup = grp.Name;
            else if (dev.Kind == DeviceKind.SmartTv) assignedGroup = TvMobileManager.SmartTvsGroupName;
            else if (dev.Kind == DeviceKind.MobileOrTablet) assignedGroup = TvMobileManager.MobileDevicesGroupName;

            TvMobileDevices.Add(new TvMobileDeviceRow(dev, info, assignedGroup));
        }

        TvTotalDevicesCount.Text = TvMobileDevices.Count.ToString();
        TvDirectProtectedCount.Text = directCount.ToString();
        TvGatewayRoutedCount.Text = gwCount.ToString();
        TvBypassingCount.Text = bypassCount.ToString();

        if (selectedDeviceIp != null)
        {
            var again = TvMobileDevices.FirstOrDefault(r => r.IpString == selectedDeviceIp);
            if (again != null) TvMobileGrid.SelectedItem = again;
        }
    }

    // ---- LAN protection state, toggle and background probe -----------------------------------

    private bool _lanBusy;
    private bool _lanFirewallOpen;
    private IReadOnlyList<NetworkProfileInfo> _lanNetworks = Array.Empty<NetworkProfileInfo>();
    private DateTime _lanProbeUtc = DateTime.MinValue;
    private bool _lanProbeRunning;

    /// <summary>Firewall and network-profile checks are slow COM calls, so they run in the background and are cached.</summary>
    private void QueueLanProbeIfStale(bool force = false)
    {
        if (_lanProbeRunning) return;
        if (!force && (DateTime.UtcNow - _lanProbeUtc).TotalSeconds < 10) return;

        _lanProbeRunning = true;
        string exe = Environment.ProcessPath ?? "";
        _ = Task.Run(() =>
        {
            bool fw = false;
            IReadOnlyList<NetworkProfileInfo> nets = Array.Empty<NetworkProfileInfo>();
            try { fw = _enforcer.HasInboundDns(exe); } catch { /* keep false */ }
            try { nets = NetworkProfileInspector.GetConnectedNetworks(); } catch { /* keep empty */ }
            return (fw, nets);
        }).ContinueWith(t =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                _lanProbeRunning = false;
                _lanProbeUtc = DateTime.UtcNow;
                if (t.IsCompletedSuccessfully)
                {
                    _lanFirewallOpen = t.Result.fw;
                    _lanNetworks = t.Result.nets;
                }
                ApplyLanBanner();
            });
        }, TaskScheduler.Default);
    }

    private void ApplyLanBanner()
    {
        string pcIp = GetLocalActiveIp()?.ToString() ?? "192.168.1.X";
        var endpoint = _sink.IsRunning ? _sink.LocalEndPoint : null;
        var status = LanProtectionEvaluator.Evaluate(endpoint, _lanFirewallOpen, _mobileServer?.IsRunning == true, _lanNetworks, pcIp);

        Brush cyan = (Brush)FindResource("Cyan");
        Brush amber = (Brush)FindResource("Amber");
        Brush muted = (Brush)FindResource("Muted");

        string warnings = status.Warnings.Count > 0 ? "\n⚠ " + string.Join("\n⚠ ", status.Warnings) : "";
        string companion = _mobileServer is { IsRunning: true }
            ? $"\nCompanion page: http://{pcIp}:{_mobileServer.Port}/ ({_mobileServer.BindScope})" +
              (_mobileServer.LastRemoteContactUtc is { } seen
                  ? $" • last phone contact {(int)(DateTime.UtcNow - seen).TotalSeconds}s ago from {_mobileServer.LastRemoteContactIp}"
                  : " • no phone has connected yet")
            : "";

        TvLanStatusSub.Text = endpoint != null ? $"DNS on {endpoint} • PC IP {pcIp}" : "DNS server stopped";
        TvLanStatusDesc.Text = status.Detail + warnings + (status.Level == LanProtectionLevel.Active ? companion : "");

        if (_lanBusy)
        {
            TvEnableLanBtn.Content = "⏳ Applying...";
            TvEnableLanBtn.IsEnabled = false;
            return;
        }

        TvEnableLanBtn.IsEnabled = true;
        TvEnableLanBtn.Visibility = Visibility.Visible;
        switch (status.Level)
        {
            case LanProtectionLevel.Active:
                TvLanStatusBanner.BorderBrush = cyan;
                TvLanStatusTitle.Text = "🟢 LAN PROTECTION ON: ";
                TvLanStatusTitle.Foreground = cyan;
                TvEnableLanBtn.Content = "🟢 LAN PROTECTION: ON  (click to turn off)";
                TvEnableLanBtn.Background = new SolidColorBrush(Color.FromArgb(0x44, 0x00, 0xE5, 0xFF));
                TvEnableLanBtn.BorderBrush = cyan;
                TvEnableLanBtn.Foreground = cyan;
                TvEnableLanBtn.ToolTip = "Other devices can use Spectra as their DNS server. Click to go back to this-PC-only.";
                break;
            case LanProtectionLevel.Partial:
                TvLanStatusBanner.BorderBrush = amber;
                TvLanStatusTitle.Text = "🟠 LAN PROTECTION PARTIAL: ";
                TvLanStatusTitle.Foreground = amber;
                TvEnableLanBtn.Content = "🛠 Repair LAN Protection (firewall)";
                TvEnableLanBtn.Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x21, 0x40));
                TvEnableLanBtn.BorderBrush = amber;
                TvEnableLanBtn.Foreground = amber;
                TvEnableLanBtn.ToolTip = "Re-creates the Windows Firewall rules for DNS (port 53) and the companion page (port 8765).";
                break;
            default:
                TvLanStatusBanner.BorderBrush = amber;
                TvLanStatusTitle.Text = "⚪ LAN PROTECTION OFF: ";
                TvLanStatusTitle.Foreground = amber;
                TvEnableLanBtn.Content = "🛡️ LAN PROTECTION: OFF  (click to turn on)";
                TvEnableLanBtn.Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x21, 0x40));
                TvEnableLanBtn.BorderBrush = amber;
                TvEnableLanBtn.Foreground = amber;
                TvEnableLanBtn.ToolTip = "Lets phones, TVs and consoles on your network use Spectra as DNS server (opens Windows Firewall for your local network only).";
                break;
        }

        TvLanStatusSub.Foreground = muted;
    }

    private static bool IsLanClient(string? client)
    {
        if (string.IsNullOrWhiteSpace(client)) return false;
        if (client.StartsWith("127.", StringComparison.Ordinal) ||
            client.StartsWith("::1", StringComparison.Ordinal) ||
            client.StartsWith("localhost", StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private void OnTvSubTabChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || TvDevicesSubPanel == null || TvInvestigationSubPanel == null) return;
        if (TvSubTabDiagnostics.IsChecked == true)
        {
            TvDevicesSubPanel.Visibility = Visibility.Collapsed;
            TvInvestigationSubPanel.Visibility = Visibility.Visible;
            RefreshTvDiagnosticsUi();
        }
        else
        {
            TvDevicesSubPanel.Visibility = Visibility.Visible;
            TvInvestigationSubPanel.Visibility = Visibility.Collapsed;
        }
    }

    private void RefreshTvDiagnosticsUi()
    {
        if (!IsLoaded || InvDnsStateBadge == null) return;

        string pcIp = GetLocalActiveIp()?.ToString() ?? "192.168.1.X";
        var ep = _sink.IsRunning ? _sink.LocalEndPoint : null;

        Brush cyan = (Brush)FindResource("Cyan");
        Brush amber = (Brush)FindResource("Amber");
        Brush text = (Brush)FindResource("Text");
        Brush muted = (Brush)FindResource("Muted");

        // 1. DNS Server
        if (_sink.IsRunning && ep != null)
        {
            if (ep.Address.Equals(IPAddress.Any))
            {
                InvDnsStateBadge.Text = "ACTIVE (0.0.0.0)";
                InvDnsStateBadge.Foreground = cyan;
                InvDnsEndpointText.Text = ep.ToString();
                InvDnsDetailText.Text = $"Listening on all LAN interfaces. Ready for {pcIp}";
            }
            else
            {
                InvDnsStateBadge.Text = "LOCALHOST ONLY";
                InvDnsStateBadge.Foreground = amber;
                InvDnsEndpointText.Text = ep.ToString();
                InvDnsDetailText.Text = "Restricted to 127.0.0.1. LAN protection is OFF.";
            }
        }
        else
        {
            InvDnsStateBadge.Text = "STOPPED";
            InvDnsStateBadge.Foreground = amber;
            InvDnsEndpointText.Text = "Offline";
            InvDnsDetailText.Text = "DNS server is not running. Click Start DNS.";
        }

        // 2. Firewall
        if (_lanFirewallOpen)
        {
            InvFwStateBadge.Text = "OPEN";
            InvFwStateBadge.Foreground = cyan;
            InvFwTitleText.Text = "LocalSubnet Inbound Allowed";
            InvFwDetailText.Text = $"Port {_sink.Settings.Port} UDP/TCP & Port {_mobileServer?.Port ?? 8765} TCP open";
        }
        else
        {
            InvFwStateBadge.Text = "MISSING";
            InvFwStateBadge.Foreground = amber;
            InvFwTitleText.Text = "Firewall Rule Missing";
            InvFwDetailText.Text = "Click 'Enable LAN Protection' to open inbound ports";
        }

        // 3. Network Profile
        var publicNet = _lanNetworks.FirstOrDefault(n => n.Category == NetworkCategoryKind.Public);
        if (publicNet != null)
        {
            InvNetStateBadge.Text = "PUBLIC (WARNING)";
            InvNetStateBadge.Foreground = amber;
            InvNetTitleText.Text = "Public Network Location";
            InvNetDetailText.Text = $"'{publicNet.Name}' is marked Public by Windows";
            InvFixNetBtn.Visibility = Visibility.Visible;
        }
        else
        {
            InvNetStateBadge.Text = "PRIVATE (OK)";
            InvNetStateBadge.Foreground = cyan;
            InvNetTitleText.Text = "Private / Domain Network";
            InvNetDetailText.Text = _lanNetworks.Count > 0 ? string.Join(", ", _lanNetworks.Select(n => n.Name)) : "Connected network";
            InvFixNetBtn.Visibility = Visibility.Collapsed;
        }

        // 4. Phone Reachability & Companion
        if (_mobileServer is { IsRunning: true })
        {
            InvCompanionStateBadge.Text = "RUNNING";
            InvCompanionStateBadge.Foreground = cyan;
            InvCompanionUrlText.Text = $"http://{pcIp}:{_mobileServer.Port}/";
            if (_mobileServer.LastRemoteContactUtc is { } seen)
            {
                int secAgo = Math.Max(0, (int)(DateTime.UtcNow - seen).TotalSeconds);
                InvLastContactText.Text = $"Contact {secAgo}s ago from {_mobileServer.LastRemoteContactIp} ({_mobileServer.RemoteRequestCount} hits)";
                InvLastContactText.Foreground = cyan;
            }
            else
            {
                InvLastContactText.Text = "Waiting for first phone / TV hit on /api/ping";
                InvLastContactText.Foreground = text;
            }
        }
        else
        {
            InvCompanionStateBadge.Text = "STOPPED";
            InvCompanionStateBadge.Foreground = muted;
            InvCompanionUrlText.Text = "Not running";
            InvLastContactText.Text = "Click Launch Companion & QR to start";
            InvLastContactText.Foreground = muted;
        }
    }

    private async void OnInvRunDnsSelfTest(object sender, RoutedEventArgs e)
    {
        var localIp = GetLocalActiveIp();
        if (localIp == null)
        {
            InvSelfTestResultText.Text = "❌ No active LAN IPv4 address detected on this PC.";
            return;
        }

        InvSelfTestResultText.Text = $"⏳ Sending UDP DNS probe to {localIp}:{_sink.Settings.Port}...";
        try
        {
            var ep = new IPEndPoint(localIp, _sink.Settings.Port);
            var res = await DnsSelfTest.RunAsync(ep, "example.com", timeout: TimeSpan.FromSeconds(2));
            if (res.Ok)
            {
                InvSelfTestResultText.Text = $"✅ DNS Self-Test PASSED! Answer received from {ep} ({string.Join(" ", res.Lines)})";
            }
            else
            {
                InvSelfTestResultText.Text = $"❌ DNS Self-Test FAILED on {ep}: {string.Join(" ", res.Lines)}. LAN Protection must be ON.";
            }
        }
        catch (Exception ex)
        {
            InvSelfTestResultText.Text = $"❌ DNS Self-Test Error: {ex.Message}";
        }
    }

    private void OnInvCopyPhonePingUrl(object sender, RoutedEventArgs e)
    {
        var localIp = GetLocalActiveIp()?.ToString() ?? "192.168.1.X";
        int port = _mobileServer?.Port ?? 8765;
        string url = $"http://{localIp}:{port}/api/ping";
        try { System.Windows.Clipboard.SetText(url); } catch { }
        Info($"📱 Phone Connectivity Link Copied!\n\n{url}\n\nOpen this link in Safari or Chrome on your phone while connected to your home Wi-Fi.\n\n• If your phone can reach this PC, you will instantly see:\n  {{\"ok\":true, \"app\":\"SpectraNetworkManager\"}}\n\n• If the page fails to load on your phone:\n  Your router has Guest Wi-Fi / Client Isolation enabled, or Windows Firewall is blocking inbound port {port}.");
    }

    private void OnInvCopyReport(object sender, RoutedEventArgs e)
    {
        var localIp = GetLocalActiveIp()?.ToString() ?? "192.168.1.X";
        var sb = new StringBuilder();
        sb.AppendLine("=== SPECTRA NETWORK MANAGER v2.0 - TV & MOBILE DIAGNOSTIC REPORT ===");
        sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"PC LAN IP: {localIp}");
        sb.AppendLine($"DNS Sinkhole Endpoint: {(_sink.IsRunning ? _sink.LocalEndPoint?.ToString() : "Stopped")}");
        sb.AppendLine($"Firewall Allowed: {_lanFirewallOpen}");
        sb.AppendLine($"Network Profiles: {string.Join(", ", _lanNetworks.Select(n => $"{n.Name} ({n.Category})"))}");
        sb.AppendLine($"Mobile Companion Server: {(_mobileServer?.IsRunning == true ? $"Port {_mobileServer.Port} ({_mobileServer.BindScope})" : "Stopped")}");
        sb.AppendLine($"Last Remote Companion Contact: {(_mobileServer?.LastRemoteContactUtc.HasValue == true ? _mobileServer.LastRemoteContactUtc.Value.ToString("s") : "None")} from {_mobileServer?.LastRemoteContactIp}");
        sb.AppendLine($"Companion Remote Hits: {_mobileServer?.RemoteRequestCount ?? 0}");
        sb.AppendLine($"Known Discovered Devices: {TvMobileDevices.Count}");
        sb.AppendLine($"LAN Queries Recorded: {TvLanActivityRows.Count}");
        try { System.Windows.Clipboard.SetText(sb.ToString()); } catch { }
        Info("Diagnostic report copied to clipboard!");
    }

    private void OnInvRefreshStatus(object sender, RoutedEventArgs e)
    {
        QueueLanProbeIfStale(force: true);
        RefreshTvMobileUi();
        RefreshTvDiagnosticsUi();
    }

    private void OnInvFixNetworkProfile(object sender, RoutedEventArgs e)
    {
        if (Confirm("Switch connected Public network(s) to Private?\n\nThis configures Windows Network Location to Private so that Windows Firewall permits local subnet DNS and companion traffic.", "Set Network to Private"))
        {
            int count = NetworkProfileInspector.SetPublicNetworksToPrivate(out string err);
            if (count > 0)
            {
                QueueLanProbeIfStale(force: true);
                RefreshTvMobileUi();
                RefreshTvDiagnosticsUi();
                Info($"Successfully changed {count} network connection(s) to Private!");
            }
            else
            {
                Info($"Could not change network profile automatically: {err}\n\nYou can also change it in Windows Settings > Network & Internet > Ethernet/Wi-Fi > Network Profile > Private.");
            }
        }
    }

    private void OnInvClearLanFeed(object sender, RoutedEventArgs e)
    {
        TvLanActivityRows.Clear();
    }

    // ---- System Audit & Stored Data Maintenance -----------------------------------------------

    private void OnSystemAuditClick(object sender, RoutedEventArgs e)
    {
        var dlg = new AuditWindow(
            auditProvider: () =>
            {
                string dataDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "SpectraNetworkManager");
                long historyBytes = 0;
                string p1 = Path.Combine(dataDir, "dns-history.db");
                string p2 = Path.Combine(dataDir, "network-history.db");
                try { if (File.Exists(p1)) historyBytes += new FileInfo(p1).Length; } catch { }
                try { if (File.Exists(p2)) historyBytes += new FileInfo(p2).Length; } catch { }

                bool anyPublic = _lanNetworks.Any(n => n.Category == NetworkCategoryKind.Public);

                var input = new AuditInput(
                    IsAdmin: _isAdmin,
                    DnsRunning: _sink.IsRunning,
                    DnsListenAddress: _sink.Settings.ListenAddress,
                    DnsPort: _sink.Settings.Port,
                    BlockBrowserDoh: _sink.Settings.BlockBrowserDoh,
                    SystemDnsSwitched: _dnsSwitch.IsActive,
                    LanFirewallOpen: _lanFirewallOpen,
                    AnyPublicNetwork: anyPublic,
                    StrictActive: StrictActive,
                    PendingAskProgramsCount: _askQueue.Count,
                    QuarantinedCount: QuarantinedItems.Count,
                    StoredHistoryBytes: historyBytes);

                return SystemAuditService.RunAudit(input);
            },
            fixHandler: async finding =>
            {
                switch (finding.Id)
                {
                    case "dns-running":
                        await StartDnsAsync();
                        break;
                    case "doh-block":
                        _sink.Settings.BlockBrowserDoh = true;
                        BlockDohBox.IsChecked = true;
                        _sink.SaveSettingsOnly(_sink.Settings);
                        break;
                    case "lan-protection":
                        await EnableLanDnsProtectionAsync();
                        break;
                    case "history-size":
                        OnCleanStoredDataClick(this, new RoutedEventArgs());
                        break;
                    case "admin-elevation":
                        OnSwitchElevationClick(this, new RoutedEventArgs());
                        break;
                }
            })
        {
            Owner = this
        };

        if (dlg.ShowDialog() == true && !string.IsNullOrEmpty(dlg.SelectedTargetTab))
        {
            switch (dlg.SelectedTargetTab)
            {
                case "Dns": DnsTab.IsChecked = true; break;
                case "TvMobile": TvMobileTab.IsChecked = true; break;
                case "Strict": StrictTab.IsChecked = true; break;
                case "Programs": ProgramsTab.IsChecked = true; break;
                case "Quarantine": QuarantineTab.IsChecked = true; break;
            }
        }
    }

    private void OnCleanStoredDataClick(object sender, RoutedEventArgs e)
    {
        string dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SpectraNetworkManager");

        var dlg = new CleanDataWindow(dataDir) { Owner = this };
        if (dlg.ShowDialog() == true && dlg.SelectedOptions is { } opt)
        {
            try
            {
                int cleanedCount = 0;
                long freedBytes = 0;

                // 1. DNS History
                if (opt.CleanDnsHistory)
                {
                    string p = Path.Combine(dataDir, "dns-history.db");
                    if (File.Exists(p))
                    {
                        freedBytes += new FileInfo(p).Length;
                        _sink.Activity.Reset();
                        DnsRows.Clear();
                        TvLanActivityRows.Clear();
                        try { File.Delete(p); } catch { }
                        cleanedCount++;
                    }
                }

                // 2. Network History
                if (opt.CleanNetworkHistory)
                {
                    string p = Path.Combine(dataDir, "network-history.db");
                    if (File.Exists(p))
                    {
                        freedBytes += new FileInfo(p).Length;
                        ConnectionHistory.Clear();
                        TopTalkers.Clear();
                        try { File.Delete(p); } catch { }
                        cleanedCount++;
                    }
                }

                // 3. AI Investigation Cache
                if (opt.CleanAiHistory)
                {
                    string p = Path.Combine(dataDir, "ai-investigations.db");
                    if (File.Exists(p))
                    {
                        freedBytes += new FileInfo(p).Length;
                        AiHistory.Clear();
                        try { File.Delete(p); } catch { }
                        cleanedCount++;
                    }
                }

                // 4. Temporary logs
                if (opt.CleanLogs)
                {
                    if (Directory.Exists(dataDir))
                    {
                        foreach (var f in Directory.GetFiles(dataDir, "*.log", SearchOption.TopDirectoryOnly))
                        {
                            try
                            {
                                freedBytes += new FileInfo(f).Length;
                                File.Delete(f);
                                cleanedCount++;
                            }
                            catch { }
                        }
                    }
                }

                // 5. Custom Rules (if opted in)
                if (opt.CleanCustomRules)
                {
                    _sink.Settings.CustomBlock.Clear();
                    _sink.Settings.CustomAllow.Clear();
                    _sink.Settings.ClientGroups.Clear();
                    _sink.SaveSettingsOnly(_sink.Settings);
                    cleanedCount++;
                }

                // 6. Quarantine (if opted in)
                if (opt.CleanQuarantine)
                {
                    foreach (var snap in _quarantineVault.GetAll())
                    {
                        _quarantineVault.DeleteSnapshot(snap.Id);
                    }
                    RefreshQuarantineVault();
                    cleanedCount++;
                }

                string freedMb = (freedBytes / (1024.0 * 1024)).ToString("F1");
                Info($"🧹 Stored Data Cleaned Successfully!\n\n• Purged {cleanedCount} storage items.\n• Reclaimed approximately {freedMb} MB of disk space.\n• UI memory views refreshed.");
            }
            catch (Exception ex)
            {
                Error("Failed to clean stored data", ex);
            }
        }
    }

    // ---- Outbound QoS Bandwidth Rate Limiter --------------------------------------------------

    private async void OnSetConnectionUploadLimit(object sender, RoutedEventArgs e)
    {
        if (ConnectionsGrid.SelectedItem is ConnectionRow row && !string.IsNullOrEmpty(row.Path))
        {
            await PromptAndApplyQosLimitAsync(row.Path);
        }
    }

    private async void OnSetProgramUploadLimit(object sender, RoutedEventArgs e)
    {
        if (ProgramsGrid.SelectedItem is ProgramRow row && !string.IsNullOrEmpty(row.Path))
        {
            await PromptAndApplyQosLimitAsync(row.Path);
        }
    }

    private async Task PromptAndApplyQosLimitAsync(string exePath)
    {
        if (!_isAdmin)
        {
            Info("Managing network speed limits requires Administrator privileges to configure Windows NetQoS policies.");
            return;
        }

        var store = QosRateLimiter.LoadStore();
        var existing = store.FirstOrDefault(x => string.Equals(x.ExePath, exePath, StringComparison.OrdinalIgnoreCase));
        long currentRate = existing?.ThrottleRateBitsPerSec ?? 0;

        var dlg = new QosSpeedDialog(exePath, currentRate) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            long newRate = dlg.SelectedBitsPerSec;
            try
            {
                if (newRate <= 0)
                {
                    await QosRateLimiter.RemoveLimitAsync(exePath);
                    Info($"Upload speed limit removed for {Path.GetFileName(exePath)}. Traffic is now unrestricted.");
                }
                else
                {
                    await QosRateLimiter.SetLimitAsync(exePath, newRate);
                    string disp = newRate >= 1_000_000 ? $"{newRate / 1_000_000.0:F1} Mbps" : $"{newRate / 1_000.0:F0} Kbps";
                    Info($"⚡ Upload speed for {Path.GetFileName(exePath)} throttled to maximum {disp} via Windows NetQoS.");
                }
            }
            catch (Exception ex)
            {
                Error("Failed to apply QoS speed limit", ex);
            }
        }
    }

    private bool _isUpdatingGuardUi;

    private void RefreshBrowserGuardUi()
    {
        bool isRegistered = BrowserExtensionHost.IsHostRegistered();
        if (isRegistered)
        {
            BrowserHostStatusBadge.Background = new SolidColorBrush(Color.FromArgb(0x22, 0x00, 0xE5, 0xFF));
            BrowserHostStatusText.Text = "🟢 Host Registered in Chrome, Edge & Firefox";
            BrowserHostStatusText.Foreground = (Brush)FindResource("Cyan");
        }
        else
        {
            BrowserHostStatusBadge.Background = new SolidColorBrush(Color.FromArgb(0x22, 0xFF, 0xB0, 0x00));
            BrowserHostStatusText.Text = "⚪ Not Registered (Click button on right to register)";
            BrowserHostStatusText.Foreground = (Brush)FindResource("Amber");
        }

        BrowserGuardRules.Clear();
        foreach (var rule in _browserGuardManager.Config.CustomRules)
        {
            BrowserGuardRules.Add(new BrowserGuardRuleRow(rule));
        }

        _isUpdatingGuardUi = true;
        try
        {
            if (GuardBlockShortsCheck != null) GuardBlockShortsCheck.IsChecked = _browserGuardManager.Config.BlockYouTubeShorts;
            if (GuardBlockStreamsCheck != null) GuardBlockStreamsCheck.IsChecked = _browserGuardManager.Config.BlockYouTubeVideoStreams;
            if (GuardBlockTikTokCheck != null) GuardBlockTikTokCheck.IsChecked = _browserGuardManager.Config.BlockSocialVideoFeeds;
            if (GuardPlaceholderCheck != null) GuardPlaceholderCheck.IsChecked = _browserGuardManager.Config.ShowInPagePlaceholder;
            if (GuardBlockAdsCheck != null) GuardBlockAdsCheck.IsChecked = _browserGuardManager.Config.CustomRules.Any(r => r.Id == "yt-ads" && r.Enabled);
            if (GuardBlockReelsCheck != null) GuardBlockReelsCheck.IsChecked = _browserGuardManager.Config.CustomRules.Any(r => r.Id == "ig-reels" && r.Enabled);
        }
        finally
        {
            _isUpdatingGuardUi = false;
        }
    }

    private async void OnEnableLanProtectionClick(object sender, RoutedEventArgs e)
    {
        string pcIp = GetLocalActiveIp()?.ToString() ?? "192.168.1.X";
        var endpoint = _sink.IsRunning ? _sink.LocalEndPoint : null;
        var status = LanProtectionEvaluator.Evaluate(endpoint, _lanFirewallOpen, _mobileServer?.IsRunning == true, _lanNetworks, pcIp);

        if (status.Level == LanProtectionLevel.Active)
        {
            if (Confirm(
                "Spectra LAN Protection is currently ACTIVE.\n\n" +
                "Smart TVs, phones and consoles on your local network are routing DNS through Spectra.\n\n" +
                "Do you want to turn LAN Protection OFF and restrict Spectra to this PC only (127.0.0.1)?",
                "Turn Off LAN Protection"))
            {
                await DisableLanDnsProtectionAsync();
            }
        }
        else
        {
            await EnableLanDnsProtectionAsync();
        }
    }

    private async Task EnableLanDnsProtectionAsync()
    {
        if (!_isAdmin)
        {
            Info("Enabling LAN Protection requires Administrator privileges to open Windows Firewall.");
            return;
        }

        _lanBusy = true;
        ApplyLanBanner();
        try
        {
            LanProtectionPlanner.ApplyEnabled(_sink.Settings);
            DnsListenBox.Text = _sink.Settings.ListenAddress;
            _sink.SaveSettingsOnly(_sink.Settings);

            bool anyPublic = _lanNetworks.Any(n => n.Category == NetworkCategoryKind.Public);
            string exe = Environment.ProcessPath ?? "";
            _enforcer.AllowInboundDns(exe, _sink.Settings.Port, _mobileServer?.Port ?? 8765, allowOnPublic: anyPublic);
            _lanFirewallOpen = true;

            if (_sink.IsRunning)
            {
                _sink.Stop();
            }
            await StartDnsAsync(_sink.Settings);

            if (_mobileServer != null && !_mobileServer.IsRunning)
            {
                try { _mobileServer.Start(); } catch { }
            }

            QueueLanProbeIfStale(force: true);
            RefreshTvMobileUi();

            var localIp = GetLocalActiveIp()?.ToString() ?? "192.168.1.X";
            string publicNote = anyPublic
                ? "\n\n⚠️ NOTE: Windows classifies your active network as 'Public'. Inbound firewall rules have been opened for your local subnet, but for best reliability consider switching the network profile to 'Private' in Windows settings."
                : "";

            Info(
                $"🛡️ LAN Protection is now ACTIVE!\n\n" +
                $"• DNS Listen Address: 0.0.0.0 (Port {_sink.Settings.Port})\n" +
                $"• Windows Firewall: Inbound DNS (Port {_sink.Settings.Port} UDP/TCP) and Mobile Companion (Port {_mobileServer?.Port ?? 8765} TCP) are OPEN for your local subnet.\n" +
                $"• Your PC LAN IP: {localIp}\n\n" +
                $"To protect your Smart TV or Phone:\n" +
                $"1. Set the device Wi-Fi/Ethernet DNS server to: {localIp}\n" +
                $"2. Leave DNS 2 (Alternative DNS) EMPTY (or set it also to {localIp})\n" +
                $"3. On Android phones: Turn OFF 'Private DNS' in Wi-Fi settings.\n\n" +
                $"Spectra is now actively ready to receive and filter all DNS traffic from your network!{publicNote}");
        }
        catch (Exception ex)
        {
            Error("Failed to enable LAN DNS protection", ex);
        }
        finally
        {
            _lanBusy = false;
            ApplyLanBanner();
        }
    }

    private async Task DisableLanDnsProtectionAsync()
    {
        if (!_isAdmin)
        {
            Info("Disabling LAN Protection requires Administrator privileges to remove Windows Firewall rules.");
            return;
        }

        _lanBusy = true;
        ApplyLanBanner();
        try
        {
            LanProtectionPlanner.ApplyDisabled(_sink.Settings);
            DnsListenBox.Text = _sink.Settings.ListenAddress;
            _sink.SaveSettingsOnly(_sink.Settings);

            string exe = Environment.ProcessPath ?? "";
            _enforcer.RemoveInboundDns(exe);
            _lanFirewallOpen = false;

            if (_sink.IsRunning)
            {
                _sink.Stop();
            }
            await StartDnsAsync(_sink.Settings);

            QueueLanProbeIfStale(force: true);
            RefreshTvMobileUi();

            Info("⚪ LAN Protection is now OFF.\n\nSpectra DNS is now restricted to this PC only (127.0.0.1). Other devices on your network will no longer be able to resolve DNS through this PC.");
        }
        catch (Exception ex)
        {
            Error("Failed to disable LAN DNS protection", ex);
        }
        finally
        {
            _lanBusy = false;
            ApplyLanBanner();
        }
    }

    private async void OnShieldAllSmartTvs(object sender, RoutedEventArgs e)
    {
        if (_sink.Settings.ListenAddress == "127.0.0.1")
        {
            if (Confirm("Spectra's DNS server is currently restricted to localhost (127.0.0.1). For Smart TVs and phones to connect, LAN listening (0.0.0.0) and Windows Firewall must be enabled.\n\nWould you like to enable LAN Protection now?", "Enable LAN Protection"))
            {
                await EnableLanDnsProtectionAsync();
            }
        }

        TvMobileManager.EnsureDefaultGroups(_sink.Settings);
        int added = 0;
        foreach (var row in TvMobileDevices.Where(d => d.Device.Kind == DeviceKind.SmartTv))
        {
            TvMobileManager.AssignDeviceToGroup(_sink.Settings, row.IpString, TvMobileManager.SmartTvsGroupName, row.Vendor, applyAcrPreset: true);
            added++;
        }

        _sink.SaveSettingsOnly(_sink.Settings);
        RefreshTvMobileUi();
        Info($"Smart TV Shield Active!\n\nAll {added} Smart TVs have been assigned to the '{TvMobileManager.SmartTvsGroupName}' group with Automatic Content Recognition (ACR) and banner ads blocked.\n\nEnsure each TV's DNS is pointed to this PC ({GetLocalActiveIp()}).");
    }

    private async void OnShieldAllMobileDevices(object sender, RoutedEventArgs e)
    {
        if (_sink.Settings.ListenAddress == "127.0.0.1")
        {
            if (Confirm("Spectra's DNS server is currently restricted to localhost (127.0.0.1). For mobile phones to connect, LAN listening (0.0.0.0) and Windows Firewall must be enabled.\n\nWould you like to enable LAN Protection now?", "Enable LAN Protection"))
            {
                await EnableLanDnsProtectionAsync();
            }
        }

        TvMobileManager.EnsureDefaultGroups(_sink.Settings);
        int added = 0;
        foreach (var row in TvMobileDevices.Where(d => d.Device.Kind == DeviceKind.MobileOrTablet))
        {
            TvMobileManager.AssignDeviceToGroup(_sink.Settings, row.IpString, TvMobileManager.MobileDevicesGroupName, row.Vendor, applyAcrPreset: true);
            added++;
        }

        _sink.SaveSettingsOnly(_sink.Settings);
        RefreshTvMobileUi();
        Info($"Mobile Defense Shield Active!\n\nAll {added} mobile devices have been assigned to the '{TvMobileManager.MobileDevicesGroupName}' group with mobile ad networks and tracking SDKs blocked.\n\nEnsure Wi-Fi DNS is pointed to this PC ({GetLocalActiveIp()}).");
    }

    private void OnInspectorPairMobileClick(object sender, RoutedEventArgs e)
    {
        OnLaunchMobileCompanion(sender, e);
    }

    private void OnInspectorShowGuideClick(object sender, RoutedEventArgs e)
    {
        if (TvMobileGrid.SelectedItem is TvMobileDeviceRow row)
        {
            var localIp = GetLocalActiveIp()?.ToString() ?? "192.168.1.X";
            string guide = TvMobileManager.GetDnsSetupGuide(row.Vendor, localIp);
            MessageBox.Show(this, guide, $"DNS Setup Guide: {row.Hostname}", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            OnShowDnsSetupGuide(sender, e);
        }
    }

    private void OnLaunchMobileCompanion(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_mobileServer != null && !_mobileServer.IsRunning)
            {
                _mobileServer.Start();
            }

            var localIp = GetLocalActiveIp();
            string ipStr = localIp?.ToString() ?? "127.0.0.1";

            var pairingWin = new MobilePairingWindow(_mobileServer!, ipStr)
            {
                Owner = this
            };
            pairingWin.ShowDialog();
        }
        catch (Exception ex)
        {
            Error("Failed to launch mobile companion server", ex);
        }
    }

    private void OnShowDnsSetupGuide(object sender, RoutedEventArgs e)
    {
        var localIp = GetLocalActiveIp()?.ToString() ?? "192.168.1.X";
        string guide = TvMobileManager.GetDnsSetupGuide(null, localIp);
        MessageBox.Show(this, guide, "DNS Setup Instructions for Smart TVs & Phones", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void OnRefreshTvMobileDevices(object sender, RoutedEventArgs e)
    {
        RefreshTvMobileUi();
        StatusText.Text = $"Refreshed {TvMobileDevices.Count} LAN devices.";
    }

    private void OnTvMobileSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (TvMobileGrid.SelectedItem is TvMobileDeviceRow row)
        {
            TvDeviceInspector.Visibility = Visibility.Visible;
            TvInspectorNameText.Text = $"{row.Hostname} ({row.DeviceTypeDisplay})";
            TvInspectorIpText.Text = $"{row.IpString} • {row.Vendor} • {row.ProtectionBadge}";
            TvInspectorGuidanceText.Text = row.ProtectionDesc;
            TvGroupAssignCombo.SelectedItem = row.AssignedGroup;
        }
    }

    private void OnCloseTvInspector(object sender, RoutedEventArgs e)
    {
        TvDeviceInspector.Visibility = Visibility.Collapsed;
    }

    private void OnAssignGroupClick(object sender, RoutedEventArgs e)
    {
        if (TvMobileGrid.SelectedItem is TvMobileDeviceRow row && TvGroupAssignCombo.SelectedItem is string selectedGroup)
        {
            TvMobileManager.AssignDeviceToGroup(_sink.Settings, row.IpString, selectedGroup, row.Vendor);
            _sink.SaveSettingsOnly(_sink.Settings);
            RefreshTvMobileUi();
            StatusText.Text = $"Assigned {row.Hostname} ({row.IpString}) to group '{selectedGroup}'.";
        }
    }

    private void OnContextShieldTv(object sender, RoutedEventArgs e)
    {
        if (TvMobileGrid.SelectedItem is TvMobileDeviceRow row)
        {
            TvMobileManager.AssignDeviceToGroup(_sink.Settings, row.IpString, TvMobileManager.SmartTvsGroupName, row.Vendor, applyAcrPreset: true);
            _sink.SaveSettingsOnly(_sink.Settings);
            RefreshTvMobileUi();
            Info($"Device '{row.Hostname}' assigned to Smart TVs group with vendor ACR blocklist applied.");
        }
    }

    private void OnContextShieldMobile(object sender, RoutedEventArgs e)
    {
        if (TvMobileGrid.SelectedItem is TvMobileDeviceRow row)
        {
            TvMobileManager.AssignDeviceToGroup(_sink.Settings, row.IpString, TvMobileManager.MobileDevicesGroupName, row.Vendor, applyAcrPreset: true);
            _sink.SaveSettingsOnly(_sink.Settings);
            RefreshTvMobileUi();
            Info($"Device '{row.Hostname}' assigned to Mobile group with tracking SDK blocklist applied.");
        }
    }

    private void OnContextPauseDevice(object sender, RoutedEventArgs e)
    {
        if (TvMobileGrid.SelectedItem is TvMobileDeviceRow row)
        {
            TvMobileManager.SetGroupBlocking(_sink.Settings, row.AssignedGroup, false);
            _sink.SaveSettingsOnly(_sink.Settings);
            RefreshTvMobileUi();
            Info($"Protection paused for group '{row.AssignedGroup}'.");
        }
    }

    private void OnContextResumeDevice(object sender, RoutedEventArgs e)
    {
        if (TvMobileGrid.SelectedItem is TvMobileDeviceRow row)
        {
            TvMobileManager.SetGroupBlocking(_sink.Settings, row.AssignedGroup, true);
            _sink.SaveSettingsOnly(_sink.Settings);
            RefreshTvMobileUi();
            Info($"Protection resumed for group '{row.AssignedGroup}'.");
        }
    }

    private void OnContextShowGuide(object sender, RoutedEventArgs e)
    {
        if (TvMobileGrid.SelectedItem is TvMobileDeviceRow row)
        {
            var localIp = GetLocalActiveIp()?.ToString() ?? "192.168.1.X";
            string guide = TvMobileManager.GetDnsSetupGuide(row.Vendor, localIp);
            MessageBox.Show(this, guide, $"DNS Setup Guide: {row.Hostname}", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void OnContextScanPorts(object sender, RoutedEventArgs e)
    {
        if (TvMobileGrid.SelectedItem is TvMobileDeviceRow row)
        {
            ScannerTab.IsChecked = true;
            OnViewChanged(this, new RoutedEventArgs());
            ScannerTargetBox.Text = row.IpString;
            ScannerProfileCombo.SelectedIndex = 1;
            OnStartScan(sender, e);
        }
    }

    private void OnContextCopyIp(object sender, RoutedEventArgs e)
    {
        if (TvMobileGrid.SelectedItem is TvMobileDeviceRow row)
        {
            System.Windows.Clipboard.SetText(row.IpString);
            StatusText.Text = $"Copied IP: {row.IpString}";
        }
    }

    // ---- Browser Guard Event Handlers ----------------------------------------

    private void OnRegisterBrowserHost(object sender, RoutedEventArgs e)
    {
        try
        {
            string hostExe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SpectraNetworkManager.BrowserHost.exe");
            if (!File.Exists(hostExe))
            {
                string altPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "SpectraNetworkManager.BrowserHost", "bin", "Debug", "net8.0-windows", "SpectraNetworkManager.BrowserHost.exe");
                if (File.Exists(altPath)) hostExe = Path.GetFullPath(altPath);
                else hostExe = Environment.ProcessPath ?? "";
            }

            if (BrowserExtensionHost.RegisterHost(hostExe, out string err))
            {
                RefreshBrowserGuardUi();
                Info("Spectra Browser Guard Host registered successfully for Chrome, Edge, and Mozilla Firefox!\n\nTo activate the extension in your browser:\n1. Click '📁 Open Extension Folder'\n2. In Chrome / Edge: Navigate to chrome://extensions, enable 'Developer Mode', and click 'Load Unpacked'.\n3. In Firefox: Navigate to about:debugging#/runtime/this-firefox, and click 'Load Temporary Add-on' selecting manifest.json.");
            }
            else
            {
                Error("Failed to register Native Messaging Host", new InvalidOperationException(err));
            }
        }
        catch (Exception ex)
        {
            Error("Registry registration error", ex);
        }
    }

    private void OnOpenExtensionFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            string extDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "extensions", "spectra-browser-guard");
            if (!Directory.Exists(extDir))
            {
                string srcExtDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "extensions", "spectra-browser-guard");
                if (Directory.Exists(srcExtDir)) extDir = Path.GetFullPath(srcExtDir);
                else Directory.CreateDirectory(extDir);
            }

            Process.Start(new ProcessStartInfo("explorer.exe", extDir) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Error("Failed to open extension directory", ex);
        }
    }

    private void OnReloadBrowserRules(object sender, RoutedEventArgs e)
    {
        _browserGuardManager.Load();
        RefreshBrowserGuardUi();
        StatusText.Text = $"Reloaded {BrowserGuardRules.Count} Browser Guard rules.";
    }

    private void OnGuardToggleChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _isUpdatingGuardUi || _browserGuardManager == null) return;
        if (GuardBlockShortsCheck == null || GuardBlockStreamsCheck == null ||
            GuardBlockAdsCheck == null || GuardBlockTikTokCheck == null ||
            GuardBlockReelsCheck == null || GuardPlaceholderCheck == null) return;

        _browserGuardManager.Config.BlockYouTubeShorts = GuardBlockShortsCheck.IsChecked == true;
        _browserGuardManager.Config.BlockYouTubeVideoStreams = GuardBlockStreamsCheck.IsChecked == true;
        _browserGuardManager.Config.BlockSocialVideoFeeds = GuardBlockTikTokCheck.IsChecked == true || GuardBlockReelsCheck.IsChecked == true;
        _browserGuardManager.Config.ShowInPagePlaceholder = GuardPlaceholderCheck.IsChecked == true;

        _browserGuardManager.ToggleRule("yt-shorts", GuardBlockShortsCheck.IsChecked == true);
        _browserGuardManager.ToggleRule("yt-video-stream", GuardBlockStreamsCheck.IsChecked == true);
        _browserGuardManager.ToggleRule("yt-ads", GuardBlockAdsCheck.IsChecked == true);
        _browserGuardManager.ToggleRule("tiktok-feed", GuardBlockTikTokCheck.IsChecked == true);
        _browserGuardManager.ToggleRule("ig-reels", GuardBlockReelsCheck.IsChecked == true);

        _browserGuardManager.Save();
    }

    private void OnAddBrowserGuardRule(object sender, RoutedEventArgs e)
    {
        string pattern = GuardPatternBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(pattern))
        {
            Info("Please enter a URL match pattern (e.g. *://*.youtube.com/shorts/* or *://*.site.com/*).");
            return;
        }

        string title = GuardTitleBox.Text.Trim();
        string resType = GuardResourceTypeCombo.SelectedItem switch
        {
            "Media / Video" => "media",
            "Sub-frame (iFrame)" => "sub_frame",
            "Script" => "script",
            "XHR / Fetch" => "xmlhttprequest",
            _ => "all"
        };

        _browserGuardManager.AddRule(title, pattern, $"Custom rule for {pattern}", GuardAction.Block, resType);
        GuardPatternBox.Text = "";
        GuardTitleBox.Text = "";
        RefreshBrowserGuardUi();
        StatusText.Text = $"Added browser block rule: {pattern}";
    }

    private void OnRemoveBrowserRuleClick(object sender, RoutedEventArgs e)
    {
        if (BrowserGuardGrid.SelectedItem is BrowserGuardRuleRow row)
        {
            if (row.IsBuiltIn)
            {
                Info("Built-in protection rules cannot be removed, but you can uncheck their 'ACTIVE' box to disable them.");
                return;
            }

            if (Confirm($"Remove rule '{row.Title}' ({row.Pattern})?", "Remove Rule"))
            {
                _browserGuardManager.RemoveRule(row.Id);
                RefreshBrowserGuardUi();
                StatusText.Text = $"Removed rule: {row.Title}";
            }
        }
    }

    private bool Confirm(string message, string title = "SpectraNetworkManager") =>
        MessageBox.Show(this, message, title, MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

    private void Warn(string message, string title = "SpectraNetworkManager") =>
        MessageBox.Show(this, message, title, MessageBoxButton.OK, MessageBoxImage.Warning);

    private static bool IsAdministrator() => ElevationHelper.IsAdministrator();

    // ---- Spectra AI & Localization System (Milestone 6) --------------------

    private void SetLanguageComboSelected(string lang)
    {
        foreach (ComboBoxItem item in LanguageCombo.Items)
        {
            if (string.Equals(item.Tag as string, lang, StringComparison.OrdinalIgnoreCase))
            {
                LanguageCombo.SelectedItem = item;
                break;
            }
        }
    }

    private void OnLanguageSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (LanguageCombo.SelectedItem is ComboBoxItem item && item.Tag is string lang)
        {
            LocalizationManager.CurrentLanguage = lang;
            _appSettings.Save(_appSettings.Settings with { Language = lang });
        }
    }

    private void ApplyLocalization()
    {
        // Update tabs
        ConnectionsTab.Content = LocalizationManager.T("TabConnections");
        ProgramsTab.Content = LocalizationManager.T("TabPrograms");
        StartupTab.Content = LocalizationManager.T("TabStartup");
        TrafficTab.Content = LocalizationManager.T("TabTraffic");
        ScannerTab.Content = LocalizationManager.T("TabScanner");
        PacketsTab.Content = LocalizationManager.T("TabPackets");
        TvMobileTab.Content = LocalizationManager.T("TabTvMobile");
        BrowserGuardTab.Content = LocalizationManager.T("TabBrowserGuard");
        AiTab.Content = LocalizationManager.T("TabAi");
        RulesTab.Content = LocalizationManager.T("TabRules");
        QuarantineTab.Content = LocalizationManager.T("TabQuarantine");
        StrictTab.Content = LocalizationManager.T("TabStrictMode");
        DnsTab.Content = LocalizationManager.T("TabDns");
        BlocksTab.Content = LocalizationManager.T("TabBlocks");

        // Update toolbar checkboxes
        AskMode.Content = LocalizationManager.T("AskModeCheck");
        AlwaysAdminCheck.Content = LocalizationManager.T("AlwaysAdminCheck");
        AlwaysOnTopCheck.Content = LocalizationManager.T("AlwaysOnTopCheck");
        NotificationSoundCheck.Content = LocalizationManager.T("AlertSoundsCheck");

        // Update AI UI elements
        AiSelectProcessLabel.Text = LocalizationManager.T("AiSelectProcess");
        AiBrowseButton.Content = "📁 " + LocalizationManager.T("AiBrowseExe");
        AiInvestigateButton.Content = LocalizationManager.T("AiRunInvestigation");
        AiAutoInvestigateCheck.Content = LocalizationManager.T("AiAutoInvestigate");
        AiTestLlmButton.Content = "🔄 " + LocalizationManager.T("AiTestOllama");
        AiRiskScoreHeader.Text = LocalizationManager.T("AiRiskScore");
        AiSummaryHeader.Text = LocalizationManager.T("AiExecutiveSummary");
        AiFindingsHeader.Text = LocalizationManager.T("AiKeyFindings");
        AiCapabilitiesHeader.Text = LocalizationManager.T("AiCapabilities");
        AiUncertaintiesHeader.Text = LocalizationManager.T("AiUncertainties");
        AiHistoryHeader.Text = LocalizationManager.T("AiHistory");
        AiClearHistoryButton.Content = LocalizationManager.T("AiClearHistory");
        AiAllowButton.Content = LocalizationManager.T("AiActionAllow");
        AiBlockButton.Content = LocalizationManager.T("AiActionBlock");
        AiQuarantineButton.Content = LocalizationManager.T("AiActionQuarantine");
        AiVirusTotalButton.Content = LocalizationManager.T("AiVirusTotal");
        AiCopyReportButton.Content = LocalizationManager.T("AiCopyJson");

        // Context Menus
        if (ConnectionMenuQuarantine != null) ConnectionMenuQuarantine.Header = LocalizationManager.T("MenuQuarantine");
        if (ProgramMenuQuarantine != null) ProgramMenuQuarantine.Header = LocalizationManager.T("MenuQuarantine");

        // Quarantine Vault
        if (QuarantineShowRestoredCheck != null) QuarantineShowRestoredCheck.Content = LocalizationManager.T("QuarantineShowRestored");
        if (QuarantineRestoreButton != null)
        {
            if (QuarantineGrid?.SelectedItem is QuarantineSnapshot snap && snap.IsRestored)
            {
                QuarantineRestoreButton.Content = "✔ Already Restored";
            }
            else
            {
                QuarantineRestoreButton.Content = LocalizationManager.T("QuarantineRestore");
            }
        }
        if (QuarantineBrowseButton != null) QuarantineBrowseButton.Content = LocalizationManager.T("QuarantineBrowse");
        if (QuarantineRemoveVaultButton != null) QuarantineRemoveVaultButton.Content = LocalizationManager.T("QuarantineRemoveVault");
        if (QuarantinePanicButton != null) QuarantinePanicButton.Content = LocalizationManager.T("QuarantinePanicRestore");

        if (_currentAiReport != null)
        {
            DisplayAiReport(_currentAiReport);
        }
    }

    private void SyncAiProcessCombo()
    {
        if (AiProcessCombo.IsDropDownOpen) return;

        var currentItems = new Dictionary<int, ComboBoxItem>();
        foreach (var obj in AiProcessCombo.Items)
        {
            if (obj is ComboBoxItem item && item.Tag is ValueTuple<int, string?> (int pid, _))
            {
                currentItems[pid] = item;
            }
        }

        var liveRows = new Dictionary<int, (string Program, string? Path)>();
        foreach (var r in Rows)
        {
            if (r.Pid > 0 && !liveRows.ContainsKey(r.Pid))
            {
                liveRows[r.Pid] = (r.Program, r.Path);
            }
        }

        int currentSelectedPid = -1;
        if (AiProcessCombo.SelectedItem is ComboBoxItem sel && sel.Tag is ValueTuple<int, string?> (int spid, _))
        {
            currentSelectedPid = spid;
        }

        var (addPids, removePids) = ItemSyncPlanner.Plan(currentItems.Keys, liveRows.Keys, currentSelectedPid);

        if (addPids.Count == 0 && removePids.Count == 0) return;

        foreach (int pid in removePids)
        {
            if (currentItems.TryGetValue(pid, out var item))
            {
                AiProcessCombo.Items.Remove(item);
            }
        }

        foreach (int pid in addPids)
        {
            if (liveRows.TryGetValue(pid, out var info))
            {
                var item = new ComboBoxItem
                {
                    Content = $"{info.Program} (PID {pid})",
                    Tag = (pid, info.Path)
                };
                AiProcessCombo.Items.Add(item);
            }
        }

        if (AiProcessCombo.SelectedItem == null && AiProcessCombo.Items.Count > 0)
        {
            if (currentSelectedPid > 0 && currentItems.TryGetValue(currentSelectedPid, out var stillThere))
            {
                AiProcessCombo.SelectedItem = stillThere;
            }
            else
            {
                AiProcessCombo.SelectedIndex = 0;
            }
        }
    }

    private void RefreshAiUi()
    {
        int targetPidToSelect = _aiSelectedPid;
        string? targetPathToSelect = _aiSelectedPath;

        AiProcessCombo.Items.Clear();

        var seenPids = new HashSet<int>();
        ComboBoxItem? matchedItem = null;

        foreach (var r in Rows)
        {
            if (r.Pid > 0 && seenPids.Add(r.Pid))
            {
                var item = new ComboBoxItem
                {
                    Content = $"{r.Program} (PID {r.Pid})",
                    Tag = (r.Pid, r.Path)
                };
                AiProcessCombo.Items.Add(item);

                if (targetPidToSelect > 0 && r.Pid == targetPidToSelect)
                {
                    matchedItem = item;
                }
                else if (matchedItem == null && !string.IsNullOrWhiteSpace(targetPathToSelect) &&
                         string.Equals(r.Path, targetPathToSelect, StringComparison.OrdinalIgnoreCase))
                {
                    matchedItem = item;
                }
            }
        }

        if (matchedItem != null)
        {
            AiProcessCombo.SelectedItem = matchedItem;
        }
        else if (targetPidToSelect > 0 || !string.IsNullOrWhiteSpace(targetPathToSelect))
        {
            string name = !string.IsNullOrWhiteSpace(targetPathToSelect) ? Path.GetFileName(targetPathToSelect) : "Process";
            string label = targetPidToSelect > 0 ? $"{name} (PID {targetPidToSelect})" : name;
            var customItem = new ComboBoxItem
            {
                Content = label,
                Tag = (targetPidToSelect, targetPathToSelect)
            };
            AiProcessCombo.Items.Insert(0, customItem);
            AiProcessCombo.SelectedItem = customItem;
        }
        else if (AiProcessCombo.Items.Count > 0 && AiProcessCombo.SelectedItem == null)
        {
            AiProcessCombo.SelectedIndex = 0;
        }
    }

    private void OnAiProcessSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (AiProcessCombo.SelectedItem is ComboBoxItem item && item.Tag is ValueTuple<int, string?> tag)
        {
            _aiSelectedPid = tag.Item1;
            _aiSelectedPath = tag.Item2;
            AiTargetDisplay.Text = _aiSelectedPid > 0
                ? $"PID {_aiSelectedPid}: {_aiSelectedPath ?? item.Content.ToString()}"
                : (_aiSelectedPath ?? item.Content.ToString());
            AiTargetTitle.Text = item.Content.ToString();
        }
    }

    private void OnAiBrowseClick(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select Executable to Investigate",
            Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*"
        };
        if (dlg.ShowDialog() == true)
        {
            _aiSelectedPath = dlg.FileName;
            _aiSelectedPid = 0;
            AiTargetDisplay.Text = dlg.FileName;
            AiTargetTitle.Text = Path.GetFileName(dlg.FileName);
        }
    }

    private async void OnRunAiInvestigationClick(object? sender, RoutedEventArgs? e)
    {
        if (_aiSelectedPid <= 0 && string.IsNullOrWhiteSpace(_aiSelectedPath))
        {
            Info("Please select a running process or browse an executable file first.");
            return;
        }

        AiInvestigateButton.IsEnabled = false;
        AiRunningIndicator.Visibility = Visibility.Visible;
        StatusText.Text = "Spectra AI: Collecting process evidence and evaluating threat telemetry...";

        try
        {
            var startupList = StartupManager.GetAllEntries();
            var sockets = _localInventory.GetLocalInventory().OpenPorts;
            var recentConns = await _historyDb.GetRecentConnectionsAsync(50);
            string lang = LocalizationManager.IsDutch ? "Nederlands" : "English";
            string model = AiModelText.Text.Trim();

            InvestigationReport report;
            if (_aiSelectedPid > 0)
            {
                report = await _aiCoordinator.InvestigatePidAsync(
                    _aiSelectedPid, lang, model, startupList, sockets, recentConns);
            }
            else
            {
                report = await _aiCoordinator.InvestigatePathAsync(
                    _aiSelectedPath!, lang, model, startupList, sockets, recentConns);
            }

            DisplayAiReport(report);
            await RefreshAiHistoryAsync();
            StatusText.Text = $"Spectra AI Investigation Complete: {report.ProcessName} — {report.FormatVerdictBadge()} (Risk: {report.RiskScore}/100)";
        }
        catch (Exception ex)
        {
            Error("AI Investigation failed", ex);
        }
        finally
        {
            AiInvestigateButton.IsEnabled = true;
            AiRunningIndicator.Visibility = Visibility.Collapsed;
        }
    }

    private void DisplayAiReport(InvestigationReport report)
    {
        _currentAiReport = report;
        AiTargetTitle.Text = $"{report.ProcessName} {(report.Pid > 0 ? $"(PID {report.Pid})" : "")}";

        // Verification Badge
        string verBadge = report.Evidence?.FormatVerificationBadge() ?? report.VerificationLevel.ToString();
        AiVerificationText.Text = verBadge;
        AiVerificationBadge.BorderBrush = report.VerificationLevel switch
        {
            IdentityVerificationLevel.VerifiedSystemBinary => (Brush)FindResource("Cyan"),
            IdentityVerificationLevel.VerifiedPublisherBinary => (Brush)FindResource("Cyan"),
            IdentityVerificationLevel.TamperedOrUntrusted => (Brush)FindResource("Magenta"),
            IdentityVerificationLevel.SuspiciousLocation => (Brush)FindResource("Magenta"),
            _ => (Brush)FindResource("Amber")
        };

        // Verdict Badge
        AiVerdictText.Text = report.FormatVerdictBadge();
        AiVerdictBadge.BorderBrush = report.Verdict switch
        {
            ThreatVerdict.Safe => (Brush)FindResource("Cyan"),
            ThreatVerdict.LowRisk => (Brush)FindResource("Cyan"),
            ThreatVerdict.Suspicious => (Brush)FindResource("Amber"),
            ThreatVerdict.Malicious => (Brush)FindResource("Magenta"),
            _ => (Brush)FindResource("Muted")
        };

        // Risk Score
        AiRiskScoreDisplay.Text = $"{report.RiskScore}/100";
        AiRiskScoreDisplay.Foreground = report.RiskScore switch
        {
            < 25 => (Brush)FindResource("Cyan"),
            < 50 => (Brush)FindResource("Text"),
            < 75 => (Brush)FindResource("Amber"),
            _ => (Brush)FindResource("Magenta")
        };

        // Executive Summary
        AiSummaryText.Text = report.ExecutiveSummary;

        // Telemetry Findings
        AiFindingsText.Text = report.KeyFindings.Count > 0
            ? string.Join("\n", report.KeyFindings.Select(f => $"• {f}"))
            : "No specific telemetry flags identified.";

        // Capabilities
        AiCapabilitiesPanel.Children.Clear();
        if (report.IdentifiedCapabilities.Count > 0)
        {
            foreach (var cap in report.IdentifiedCapabilities)
            {
                var border = new Border
                {
                    Background = (Brush)FindResource("Selected"),
                    BorderBrush = (Brush)FindResource("Cyan"),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(3),
                    Padding = new Thickness(8, 2, 8, 2),
                    Margin = new Thickness(0, 0, 8, 4)
                };
                border.Child = new TextBlock
                {
                    Text = cap,
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = (Brush)FindResource("Cyan")
                };
                AiCapabilitiesPanel.Children.Add(border);
            }
        }
        else
        {
            AiCapabilitiesPanel.Children.Add(new TextBlock
            {
                Text = "None recorded",
                FontSize = 11,
                Foreground = (Brush)FindResource("Muted")
            });
        }

        // Uncertainties
        AiUncertaintiesText.Text = report.Uncertainties.Count > 0
            ? string.Join("\n", report.Uncertainties.Select(u => $"⚠ {u}"))
            : "None reported (high confidence).";
    }

    private async void OnAiTestLlmClick(object sender, RoutedEventArgs e)
    {
        AiTestLlmButton.IsEnabled = false;
        StatusText.Text = "Testing connection to local Ollama API...";
        try
        {
            _aiCoordinator.Ollama.DefaultModel = AiModelText.Text.Trim();
            bool available = await _aiCoordinator.Ollama.IsAvailableAsync();
            if (available)
            {
                var models = await _aiCoordinator.Ollama.GetAvailableModelsAsync();
                string modelList = models.Count > 0 ? string.Join(", ", models.Take(3)) : "online";
                AiOllamaStatusText.Text = $"🟢 Ollama Connected: {modelList}";
                AiOllamaStatusText.Foreground = (Brush)FindResource("Cyan");
                StatusText.Text = $"Ollama is online! Found {models.Count} model(s): {modelList}";
            }
            else
            {
                AiOllamaStatusText.Text = "⚪ Offline Deterministic Engine (Ollama Offline)";
                AiOllamaStatusText.Foreground = (Brush)FindResource("Muted");
                StatusText.Text = "Ollama is not running on 127.0.0.1:11434. Spectra AI will use the Deterministic Offline Engine.";
            }
        }
        catch (Exception ex)
        {
            Error("Error connecting to Ollama", ex);
        }
        finally
        {
            AiTestLlmButton.IsEnabled = true;
        }
    }

    private async Task CheckOllamaStatusAsync()
    {
        try
        {
            bool ready = await _aiCoordinator.Ollama.IsAvailableAsync();
            Dispatcher.Invoke(() =>
            {
                if (ready)
                {
                    AiOllamaStatusText.Text = $"🟢 Ollama Connected ({_aiCoordinator.Ollama.DefaultModel})";
                    AiOllamaStatusText.Foreground = (Brush)FindResource("Cyan");
                }
                else
                {
                    AiOllamaStatusText.Text = "⚪ Offline Deterministic Engine (Ollama Offline)";
                    AiOllamaStatusText.Foreground = (Brush)FindResource("Muted");
                }
            });
        }
        catch { }
    }

    private void OnAiAutoInvestigateChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        bool enabled = AiAutoInvestigateCheck.IsChecked == true;
        _appSettings.Save(_appSettings.Settings with { AiAutoInvestigateUnverified = enabled });
    }

    private void OnAiAllowProgramClick(object sender, RoutedEventArgs e)
    {
        string? path = _currentAiReport?.Evidence?.ExecutablePath ?? _aiSelectedPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            Info("No executable path available to allow.");
            return;
        }
        _rules.Set(new ProgramRule(path, RuleAction.Allow, DateTimeOffset.Now));
        _enforcer.Unblock(path);
        StatusText.Text = $"Allowed program in firewall rules: {Path.GetFileName(path)}";
    }

    private void OnAiBlockProgramClick(object sender, RoutedEventArgs e)
    {
        string? path = _currentAiReport?.Evidence?.ExecutablePath ?? _aiSelectedPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            Info("No executable path available to block.");
            return;
        }
        _rules.Set(new ProgramRule(path, RuleAction.Block, DateTimeOffset.Now, null, RuleDirection.Outbound, null));
        var plan = RulePlanner.Plan(RuleDirection.Outbound, TrafficScope.All);
        _enforcer.Block(path, plan);
        StatusText.Text = $"Blocked outbound traffic for: {Path.GetFileName(path)}";
    }

    private async void OnAiQuarantineProgramClick(object sender, RoutedEventArgs e)
    {
        string? path = _currentAiReport?.Evidence?.ExecutablePath ?? _aiSelectedPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            Info("No executable path available to quarantine.");
            return;
        }
        await PromptAndQuarantineAsync(path, Path.GetFileName(path), "Quarantined via Spectra AI");
        await RefreshAiHistoryAsync();
    }

    private void OnAiVirusTotalClick(object sender, RoutedEventArgs e)
    {
        string? sha256 = _currentAiReport?.Evidence?.Sha256;
        if (string.IsNullOrWhiteSpace(sha256) && !string.IsNullOrWhiteSpace(_aiSelectedPath))
        {
            sha256 = _hashCache.GetSha256(_aiSelectedPath);
        }
        if (!string.IsNullOrWhiteSpace(sha256))
        {
            string url = ExecutableHashCache.GetVirusTotalUrl(sha256);
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            StatusText.Text = $"Opened VirusTotal for SHA-256: {sha256}";
        }
        else
        {
            Info("No SHA-256 hash available for this target.");
        }
    }

    private static readonly System.Text.Json.JsonSerializerOptions AiJsonOptions = new() { WriteIndented = true };

    private void OnAiCopyReportClick(object sender, RoutedEventArgs e)
    {
        if (_currentAiReport == null)
        {
            Info("No investigation report to copy.");
            return;
        }
        string json = System.Text.Json.JsonSerializer.Serialize(_currentAiReport, AiJsonOptions);
        System.Windows.Clipboard.SetText(json);
        StatusText.Text = "Copied full AI investigation JSON report to clipboard.";
    }

    private async Task RefreshAiHistoryAsync()
    {
        try
        {
            var list = await _aiDb.GetRecentInvestigationsAsync(50);
            AiHistory.Clear();
            foreach (var r in list)
            {
                AiHistory.Add(new AiInvestigationViewModel(
                    r.Id,
                    r.Timestamp.ToLocalTime().ToString("HH:mm:ss"),
                    r.ProcessName,
                    r.FormatVerdictBadge(),
                    r.RiskScore,
                    r.ModelUsed,
                    r));
            }
        }
        catch { }
    }

    private void OnAiHistorySelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (AiHistoryGrid.SelectedItem is AiInvestigationViewModel vm)
        {
            DisplayAiReport(vm.Report);
        }
    }

    private async void OnAiClearHistoryClick(object sender, RoutedEventArgs e)
    {
        if (Confirm("Clear all AI investigation history?", "Clear History"))
        {
            await _aiDb.ClearAllAsync();
            AiHistory.Clear();
            StatusText.Text = "Cleared all AI investigation history records.";
        }
    }

    private void OnContextMenuInvestigateAi(object sender, RoutedEventArgs e)
    {
        int targetPid = 0;
        string? targetPath = null;
        string targetName = "";

        // Determine which grid triggered this context menu action
        DataGrid? sourceGrid = null;
        if (sender is MenuItem mi && mi.Parent is ContextMenu cm && cm.PlacementTarget is DataGrid dg)
        {
            sourceGrid = dg;
        }

        // Prioritize by active tab or triggering source grid so other tabs take precedence over ConnectionsGrid
        if ((sourceGrid == ProgramsGrid || ProgramsTab.IsChecked == true) && ProgramsGrid.SelectedItem is ProgramRow progRow)
        {
            targetPath = progRow.Path;
            targetName = progRow.Name;
        }
        else if ((sourceGrid == StartupGrid || StartupTab.IsChecked == true) && StartupGrid.SelectedItem is StartupRow startRow)
        {
            targetPath = startRow.ExecutablePath;
            targetName = startRow.Name;
        }
        else if ((sourceGrid == RulesGrid || RulesTab.IsChecked == true) && RulesGrid.SelectedItem is RuleRow ruleRow)
        {
            targetPath = ruleRow.Path;
            targetName = ruleRow.Name;
        }
        else if ((sourceGrid == QuarantineGrid || QuarantineTab.IsChecked == true) && QuarantineGrid.SelectedItem is QuarantineSnapshot qSnap)
        {
            targetPath = qSnap.ExecutablePath;
            targetName = qSnap.ProgramName;
        }
        else if ((sourceGrid == PacketsGrid || PacketsTab.IsChecked == true) && PacketsGrid.SelectedItem is PacketRow pktRow)
        {
            targetPid = pktRow.Packet.ProcessId ?? 0;
            targetName = pktRow.Packet.ProcessName ?? pktRow.ProcessDisplay;
            if (string.IsNullOrWhiteSpace(targetName) || targetName == "-")
                targetName = pktRow.HostOrSni ?? pktRow.Info;
        }
        else if ((sourceGrid == TopTalkersGrid || TrafficTab.IsChecked == true) && TopTalkersGrid.SelectedItem is TopTalkerViewModel talkerRow)
        {
            targetPath = talkerRow.Program;
            targetName = talkerRow.ProgramName;
        }
        else if ((sourceGrid == ConnectionHistoryGrid || TrafficTab.IsChecked == true) && ConnectionHistoryGrid.SelectedItem is ConnectionHistoryViewModel histRow)
        {
            targetPath = histRow.Program;
            targetName = histRow.ProgramName;
        }
        else if ((sourceGrid == BlocksGrid || BlocksTab.IsChecked == true) && BlocksGrid.SelectedItem is BlockRow blockRow)
        {
            targetPid = blockRow.Pid;
            targetPath = blockRow.Application;
            targetName = System.IO.Path.GetFileName(blockRow.Application);
        }
        else if (ConnectionsGrid.SelectedItem is ConnectionRow connRow)
        {
            targetPid = connRow.Pid;
            targetPath = connRow.Path;
            targetName = connRow.Program;
        }

        // Correlate: if targetPath is known but targetPid == 0, check if it's currently running in connection rows
        if (targetPid <= 0 && !string.IsNullOrWhiteSpace(targetPath))
        {
            var runningMatch = Rows.FirstOrDefault(r => r.Pid > 0 && string.Equals(r.Path, targetPath, StringComparison.OrdinalIgnoreCase));
            if (runningMatch != null)
            {
                targetPid = runningMatch.Pid;
                if (string.IsNullOrWhiteSpace(targetName)) targetName = runningMatch.Program;
            }
        }

        // If targetPid > 0 but path is empty, correlate with active rows
        if (targetPid > 0 && string.IsNullOrWhiteSpace(targetPath))
        {
            var runningMatch = Rows.FirstOrDefault(r => r.Pid == targetPid);
            if (runningMatch != null && !string.IsNullOrWhiteSpace(runningMatch.Path))
            {
                targetPath = runningMatch.Path;
                if (string.IsNullOrWhiteSpace(targetName) || targetName == "-") targetName = runningMatch.Program;
            }
        }

        _aiSelectedPid = targetPid;
        _aiSelectedPath = targetPath;

        AiTab.IsChecked = true;
        OnViewChanged(AiTab, new RoutedEventArgs());

        // Explicitly ensure the combobox reflects the target
        if (targetPid > 0)
        {
            foreach (ComboBoxItem item in AiProcessCombo.Items)
            {
                if (item.Tag is ValueTuple<int, string?> tag && tag.Item1 == targetPid)
                {
                    AiProcessCombo.SelectedItem = item;
                    break;
                }
            }
        }
        else if (!string.IsNullOrWhiteSpace(targetPath))
        {
            foreach (ComboBoxItem item in AiProcessCombo.Items)
            {
                if (item.Tag is ValueTuple<int, string?> tag && string.Equals(tag.Item2, targetPath, StringComparison.OrdinalIgnoreCase))
                {
                    AiProcessCombo.SelectedItem = item;
                    break;
                }
            }
        }

        // If not found in combobox, insert it at the top and select it
        if (AiProcessCombo.SelectedItem == null && (targetPid > 0 || !string.IsNullOrWhiteSpace(targetPath)))
        {
            string label = targetPid > 0
                ? $"{targetName} (PID {targetPid})"
                : $"{targetName} (Executable)";
            var customItem = new ComboBoxItem
            {
                Content = label,
                Tag = (targetPid, targetPath)
            };
            AiProcessCombo.Items.Insert(0, customItem);
            AiProcessCombo.SelectedItem = customItem;
        }

        _aiSelectedPid = targetPid;
        _aiSelectedPath = targetPath;
        AiTargetDisplay.Text = targetPid > 0 ? $"PID {targetPid}: {targetName} ({targetPath})" : (targetPath ?? targetName);
        AiTargetTitle.Text = !string.IsNullOrWhiteSpace(targetName) ? targetName : System.IO.Path.GetFileName(targetPath ?? "");

        OnRunAiInvestigationClick(this, new RoutedEventArgs());
    }
}

public sealed record AiInvestigationViewModel(
    string Id,
    string TimestampDisplay,
    string ProcessName,
    string VerdictDisplay,
    int RiskScore,
    string ModelUsed,
    InvestigationReport Report);
