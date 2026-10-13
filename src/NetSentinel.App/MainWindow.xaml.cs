using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Windows;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Threading;
using NetSentinel.Core;
using NetSentinel.Platform.Windows;
using NetSentinel.Sinkhole;

namespace NetSentinel.Ui;

public partial class MainWindow : Window
{
    private const int MaxEventLines = 300;

    private readonly ConnectionMonitor _monitor = new(new IpHelperConnectionSource(), new ProcessResolver());
    private readonly FirewallBlockLog _blockLog = new();
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
    private readonly bool _isAdmin = IsAdministrator();

    // Ask mode: programs waiting for an Allow / Block answer
    private readonly Queue<ProgramSummary> _askQueue = new();
    private readonly HashSet<string> _askQueued = new(StringComparer.OrdinalIgnoreCase);
    private ProgramSummary? _askCurrent;

    private IReadOnlyList<ConnectionView> _lastConnections = Array.Empty<ConnectionView>();
    private bool _busy;

    public ObservableCollection<ConnectionRow> Rows { get; } = new();
    public ObservableCollection<ProgramRow> Programs { get; } = new();
    public ObservableCollection<RuleRow> RuleRows { get; } = new();
    public ObservableCollection<PublisherRow> Publishers { get; } = new();
    public ObservableCollection<DnsRow> DnsRows { get; } = new();
    public ObservableCollection<EventLine> Events { get; } = new();
    public ObservableCollection<BlockRow> Blocks { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;

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

        _dns.Resolved += OnHostResolved;
        _signatures.Verified += OnSignatureVerified;
        Closed += (_, _) =>
        {
            _signatures.Dispose();
            _sink.Dispose();
        };

        _timer.Tick += async (_, _) => await TickAsync();
        Loaded += async (_, _) =>
        {
            await RecoverStrictStateAsync();
            LoadDnsSettingsIntoUi();
            if (_sink.Settings.AutoStart) await StartDnsAsync();
            await TickAsync();
            _timer.Start();
        };
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

            _tickCount++;
            if (StrictActive && _isAdmin && _tickCount % 2 == 0) _ = PollBlockedAsync();
            RefreshDnsUi();
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
        foreach (var closed in tick.Closed)
        {
            var key = ConnectionKey.From(closed.Connection);
            if (_rows.Remove(key, out var gone)) Rows.Remove(gone);
            if (!IsNoise(closed)) AddEvent(tick.Time, "-", closed, opened: false);
        }

        bool resolve = ResolveHosts.IsChecked == true;
        foreach (var view in tick.Connections)
        {
            var key = ConnectionKey.From(view.Connection);
            if (_rows.TryGetValue(key, out var existing))
            {
                existing.StateValue = view.Connection.State;
                continue;
            }

            var row = new ConnectionRow(view);
            if (row.Path.Length > 0) row.SetSignature(_signatures.TryGet(row.Path));
            if (resolve && row.RemoteAddress is not null)
                row.Host = _dns.Request(row.RemoteAddress) ?? "";
            _rows[key] = row;
            Rows.Add(row);
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
        string admin = _isAdmin ? "Administrator" : "Not elevated (blocking, some program names and the Firewall blocks view need Administrator)";
        StatusText.Text = $"{strict}{Rows.Count} entries  |  {established} established  |  {listening} listening  |  {processes} processes  |  {undecided} programs without a decision  |  {admin}";
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
            AddAlert(time, $"{baseline} programs were already online when NetSentinel started (see Programs view)");

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

    // ---- decisions: allow / block / forget / panic -----------------------------------------
    // Each Try... method returns true only if it really changed something, and shows its own error message otherwise.

    private bool TryAllow(string path, string name, ProgramRule? existing)
    {
        if (string.IsNullOrEmpty(path))
        {
            Info("This program's file path is unknown. Run NetSentinel as Administrator so Windows reveals it.");
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
            Info("Blocking changes Windows Firewall, which needs Administrator rights.\n\nClose NetSentinel and start it again with 'Run as administrator'.");
            return false;
        }

        var dialog = new BlockDialog(this, name, path, existing);
        if (dialog.ShowDialog() != true) return false;

        try
        {
            var plan = RulePlanner.Plan(dialog.Direction, dialog.Scope);
            _enforcer.Block(path, plan);

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

    // -- panic --

    private async void OnPanic(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            Info("Undoing firewall changes needs Administrator rights.\n\nClose NetSentinel and start it again with 'Run as administrator'.");
            return;
        }

        var answer = MessageBox.Show(this,
            "Undo everything NetSentinel changed in Windows Firewall?\n\n" +
            "- strict mode is switched off\n" +
            "- every firewall rule NetSentinel created (blocks and allows) is removed\n\n" +
            "Your 'Allowed' decisions stay in NetSentinel's list; block decisions are cleared.",
            "Panic: undo all changes", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        try
        {
            // Restore the default first, so nothing stays locked while the rules are being removed.
            if (_strict.State.Phase != StrictPhase.Off || _strict.WasUnreadable)
                await DisableStrictAsync();

            int removed = await Task.Run(() => _enforcer.RemoveAll());
            int cleared = _rules.RemoveWhere(r => r.Action == RuleAction.Block);
            StatusText.Text = $"Removed {removed} firewall rules and cleared {cleared} block decisions. Strict mode is off.";
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
        MessageBox.Show(this, message, "NetSentinel", MessageBoxButton.OK, MessageBoxImage.Information);

    private void Error(string what, Exception ex) =>
        MessageBox.Show(this, $"{what}.\n\n{ex.Message}", "NetSentinel", MessageBoxButton.OK, MessageBoxImage.Error);

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
            _ => "Strict mode is OFF. Programs without a decision keep their network access; NetSentinel only watches and asks.",
        };

        StrictEnableButton.IsEnabled = state.Phase == StrictPhase.Off;
        StrictDisableButton.IsEnabled = state.Phase != StrictPhase.Off;
    }

    // Runs once at start: finishes or undoes whatever a previous run left behind.
    private async Task RecoverStrictStateAsync()
    {
        if (_strict.WasUnreadable)
            Info("The saved strict-mode state could not be read, so NetSentinel does not know whether strict mode is on.\n\nIf your network access is restricted, start NetSentinel as Administrator and press the PANIC button.");

        var state = _strict.State;
        if (state.Phase == StrictPhase.Pending)
        {
            if (!_isAdmin)
            {
                Info("Strict mode was switched on but never confirmed, and switching it off needs Administrator rights.\n\nClose NetSentinel and start it again with 'Run as administrator'. It will then switch strict mode off by itself.");
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
        try { return _blockLog.ReadRecent(TimeSpan.FromDays(1), 1).FirstOrDefault()?.RecordId ?? 0; }
        catch (Exception) { return 0; }
    }

    private async void OnStrictEnable(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            Info("Strict mode changes Windows Firewall, which needs Administrator rights.\n\nClose NetSentinel and start it again with 'Run as administrator'.");
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
    private DnsLogEntry? _dnsLastTop;
    private bool _dnsBusy;

    private void LoadDnsSettingsIntoUi()
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
        ListsBox.Text = string.Join("\r\n", c.Lists.Select(l => (l.Enabled ? "" : "# ") + l.Name + " | " + l.Url));
        CustomBlockBox.Text = string.Join("\r\n", c.CustomBlock);
        CustomAllowBox.Text = string.Join("\r\n", c.CustomAllow);
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

        settings = new DnsSettings
        {
            AutoStart = AutoStartDnsBox.IsChecked == true,
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

    private async void OnDnsStart(object sender, RoutedEventArgs e) => await StartDnsAsync();

    private void OnDnsStop(object sender, RoutedEventArgs e)
    {
        _sink.Stop();
        StatusText.Text = "DNS server stopped.";
        RefreshDnsUi();
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

    private void OnDnsClearLog(object sender, RoutedEventArgs e)
    {
        _sink.Activity.Reset();
        DnsRows.Clear();
        _dnsLastTop = null;
        RefreshDnsUi();
    }

    private async void OnDnsAllow(object sender, RoutedEventArgs e) => await ChangeDnsRuleAsync(allow: true);

    private async void OnDnsBlock(object sender, RoutedEventArgs e) => await ChangeDnsRuleAsync(allow: false);

    private async Task ChangeDnsRuleAsync(bool allow)
    {
        if (DnsGrid.SelectedItem is not DnsRow row)
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
        }
        catch (Exception ex)
        {
            Error("Could not change the rule", ex);
        }
    }

    private void OnDnsCheck(object sender, RoutedEventArgs e) => DnsCheckResult.Text = _sink.Check(DnsCheckBox.Text);

    private void OnDnsAllowLan(object sender, RoutedEventArgs e)
    {
        if (!_isAdmin)
        {
            Info("Changing Windows Firewall needs Administrator rights.\n\nClose NetSentinel and start it again with 'Run as administrator'.");
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

    // The badge is cheap and always current; the rest only matters while the DNS tab is visible.
    private void RefreshDnsUi()
    {
        DnsBadge.Visibility = _sink.IsRunning ? Visibility.Visible : Visibility.Collapsed;
        if (DnsPanel.Visibility != Visibility.Visible) return;

        DnsStartButton.IsEnabled = !_sink.IsRunning && !_dnsBusy;
        DnsStopButton.IsEnabled = _sink.IsRunning;
        DnsTestButton.IsEnabled = _sink.IsRunning && !_dnsBusy;

        DnsStatus.Text = _sink.IsRunning
            ? $"DNS server is RUNNING on {_sink.LocalEndPoint}"
            : "DNS server is stopped. Point your DNS at it to start blocking.";

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
        for (int i = known - 1; i >= 0; i--) DnsRows.Insert(0, DnsRow.From(recent[i]));
        while (DnsRows.Count > 500) DnsRows.RemoveAt(DnsRows.Count - 1);
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
                    row.Host = name;
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
        string q = SearchBox.Text.Trim();
        if (q.Length == 0) return true;
        return p.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
            || p.Path.Contains(q, StringComparison.OrdinalIgnoreCase)
            || p.Signer.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    // These handlers can fire while the XAML is still being loaded, so ignore them until the window is ready.
    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        _rowsView.Refresh();
        _programsView.Refresh();
    }

    private async void OnViewChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        ConnectionsPanel.Visibility = ConnectionsTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ProgramsPanel.Visibility = ProgramsTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        RulesPanel.Visibility = RulesTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        StrictPanel.Visibility = StrictTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        DnsPanel.Visibility = DnsTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        BlocksPanel.Visibility = BlocksTab.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;

        if (StrictTab.IsChecked == true) UpdateStrictUi();
        if (DnsTab.IsChecked == true) RefreshDnsUi();
        if (RulesTab.IsChecked == true) await RefreshRulesAsync();
        if (BlocksTab.IsChecked == true) await LoadBlocksAsync();
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

            BlocksHint.Text = events.Count > 0
                ? $"{events.Count} blocked connections in the last hour (newest first)."
                : "Nothing blocked in the last hour. If you expected blocks, enable auditing once: see README, section \"Firewall blocks\".";
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

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
