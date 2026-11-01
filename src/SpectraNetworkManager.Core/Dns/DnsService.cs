using System.Net;

namespace SpectraNetworkManager.Sinkhole;

/// <summary>
/// Everything the DNS sinkhole needs in one place: settings, block lists, the server, the cache and the activity log.
/// The window talks only to this class.
/// </summary>
public sealed class DnsService : IDisposable
{
    private readonly DnsSettingsStore _store;
    private readonly TvMobileRulesStore _tvMobileStore;
    private readonly BlocklistManager _lists;
    private readonly DnsHistoryDatabase _historyDb;
    private readonly HttpMessageHandler? _httpHandler;
    private CompositeUpstreamResolver? _compositeResolver;
    private DnsServer? _server;
    private volatile DomainFilter _baseSubscriptionFilter = DomainFilter.Empty;
    private volatile DomainFilter _filter = DomainFilter.Empty;
    private volatile DomainFilter _tvMobileFilter = DomainFilter.Empty;
    private IReadOnlyList<string> _baseFilterNotes = Array.Empty<string>();

    public DnsService(
        string settingsFile,
        string listsFolder,
        HttpMessageHandler? handler = null,
        string? historyDbPath = null,
        string? tvMobileRulesFile = null)
    {
        _store = new DnsSettingsStore(settingsFile);
        string defaultTvPath = Path.Combine(Path.GetDirectoryName(settingsFile) ?? "", "tv-mobile-rules.json");
        _tvMobileStore = new TvMobileRulesStore(
            tvMobileRulesFile ?? (string.Equals(settingsFile, DnsSettingsStore.DefaultPath, StringComparison.OrdinalIgnoreCase)
                ? TvMobileRulesStore.DefaultPath
                : defaultTvPath));
        _lists = new BlocklistManager(listsFolder, handler);
        _httpHandler = handler;
        _historyDb = new DnsHistoryDatabase(historyDbPath ?? DnsHistoryDatabase.DefaultPath);
        Settings = _store.Load();
        TvMobileRules = _tvMobileStore.Load();
        Cache = new DnsCache(Settings.CacheEntries);
        ReloadFilter();
    }

    public static DnsService CreateDefault() => new(DnsSettingsStore.DefaultPath, BlocklistManager.DefaultFolder);

    private DateTimeOffset _blockingPausedUntil = DateTimeOffset.MinValue;
    private CancellationTokenSource? _pauseTimerCts;

    public DnsSettings Settings { get; private set; }
    public TvMobileRulesConfig TvMobileRules { get; private set; }
    public string PcRulesFilePath => _store.FilePath;
    public string TvMobileRulesFilePath => _tvMobileStore.FilePath;
    public DnsActivity Activity { get; } = new();
    public DnsCache Cache { get; private set; }
    public FilterLoadInfo? FilterInfo { get; private set; }

    public bool IsRunning => _server?.IsRunning == true;
    public IPEndPoint? LocalEndPoint => _server?.LocalEndPoint;
    public int BlockedDomainCount => _filter.BlockedDomainCount;
    public int TvMobileBlockedDomainCount => _tvMobileFilter.BlockedDomainCount;

    public bool IsBlockingPaused => _blockingPausedUntil > DateTimeOffset.UtcNow;
    public DateTimeOffset? BlockingPausedUntil => IsBlockingPaused ? _blockingPausedUntil : null;
    public TimeSpan? BlockingPauseRemaining => IsBlockingPaused ? _blockingPausedUntil - DateTimeOffset.UtcNow : null;

    public BlocklistManager Lists => _lists;

    /// <summary>Raised for every answered query (on a background thread).</summary>
    public event Action<DnsLogEntry>? Queried;

    /// <summary>Raised when blocking pause status changes (true = paused, false = resumed).</summary>
    public event Action<bool>? BlockingPauseChanged;

    /// <summary>Temporarily disables DNS domain blocking for the specified duration.</summary>
    public void PauseBlocking(TimeSpan duration)
    {
        _pauseTimerCts?.Cancel();
        _pauseTimerCts?.Dispose();

        _blockingPausedUntil = DateTimeOffset.UtcNow + duration;
        Cache.Clear();

        var cts = new CancellationTokenSource();
        _pauseTimerCts = cts;
        _ = Task.Delay(duration, cts.Token).ContinueWith(t =>
        {
            if (t.IsCompletedSuccessfully)
            {
                _blockingPausedUntil = DateTimeOffset.MinValue;
                Cache.Clear();
                BlockingPauseChanged?.Invoke(false);
            }
        }, TaskScheduler.Default);

        BlockingPauseChanged?.Invoke(true);
    }

    /// <summary>Resumes DNS domain blocking immediately.</summary>
    public void ResumeBlocking()
    {
        _pauseTimerCts?.Cancel();
        _pauseTimerCts?.Dispose();
        _pauseTimerCts = null;

        if (_blockingPausedUntil > DateTimeOffset.UtcNow)
        {
            _blockingPausedUntil = DateTimeOffset.MinValue;
            Cache.Clear();
            BlockingPauseChanged?.Invoke(false);
        }
    }

    /// <summary>Loads the block lists, then starts answering. Throws if the settings are invalid or the port is already in use.</summary>
    public async Task StartAsync()
    {
        if (IsRunning) return;
        if (!Settings.Validate(out string error)) throw new InvalidOperationException(error);

        await Task.Run(ReloadFilter).ConfigureAwait(false);       // load the lists first, so no query slips through unfiltered

        if (Settings.QueryHistoryRetentionDays > 0)
        {
            _ = Task.Run(() => _historyDb.PruneOlderThanDaysAsync(Settings.QueryHistoryRetentionDays));
        }

        Cache = new DnsCache(Settings.CacheEntries);
        _compositeResolver?.Dispose();
        _compositeResolver = CompositeUpstreamResolver.FromStrings(Settings.Upstreams, timeout: TimeSpan.FromSeconds(3), httpHandler: _httpHandler);

        var server = new DnsServer(
            Settings,
            () => _filter,
            _compositeResolver,
            Cache,
            Activity,
            () => IsBlockingPaused,
            historyDb: _historyDb,
            lanFilter: () => _tvMobileFilter);

        server.Queried += e => Queried?.Invoke(e);
        server.Start();
        _server = server;
    }

    public void Stop()
    {
        _server?.Dispose();
        _server = null;
        _compositeResolver?.Dispose();
        _compositeResolver = null;
    }

    public void Dispose()
    {
        _pauseTimerCts?.Cancel();
        _pauseTimerCts?.Dispose();
        _pauseTimerCts = null;
        Stop();
        _historyDb.Dispose();
    }

    private void ReloadFilter()
    {
        var baseFilter = _lists.LoadFilterWithCustomRules(Settings, Array.Empty<string>(), Array.Empty<string>(), out var baseInfo);
        _baseSubscriptionFilter = baseFilter;
        _baseFilterNotes = baseInfo.Notes;
        RefreshCustomFilters();
    }

    private void RefreshCustomFilters()
    {
        var baseFilter = _baseSubscriptionFilter;
        var pcFilter = baseFilter.WithOverrides(Settings.CustomBlock, Settings.CustomAllow);
        var tvFilter = baseFilter.WithOverrides(TvMobileRules.CustomBlock, TvMobileRules.CustomAllow);
        _filter = pcFilter;
        _tvMobileFilter = tvFilter;
        FilterInfo = new FilterLoadInfo(pcFilter.BlockedDomainCount, pcFilter.AllowedDomainCount, pcFilter.RegexCount, _baseFilterNotes);
    }

    /// <summary>Saves new settings. If the server is running it is restarted so listen address, port and upstreams take effect.</summary>
    public async Task ApplySettingsAsync(DnsSettings settings)
    {
        if (!settings.Validate(out string error)) throw new InvalidOperationException(error);

        bool wasRunning = IsRunning;
        if (wasRunning) Stop();

        _store.Save(settings);
        Settings = settings;

        if (wasRunning) await StartAsync().ConfigureAwait(false);
        else await Task.Run(ReloadFilter).ConfigureAwait(false);
    }

    /// <summary>Saves settings to disk and updates in-memory settings without restarting the DNS server.</summary>
    public void SaveSettingsOnly(DnsSettings settings)
    {
        _store.Save(settings);
        Settings = settings;
    }

    public async Task<IReadOnlyList<ListUpdateResult>> UpdateListsAsync(CancellationToken ct = default)
    {
        var results = await _lists.UpdateAsync(Settings.Lists, ct).ConfigureAwait(false);
        await Task.Run(ReloadFilter, ct).ConfigureAwait(false);
        Cache.Clear();                                              // answers cached before may now be blocked
        return results;
    }

    /// <summary>Subscribes to a blocklist URL, downloads it, and activates it immediately.</summary>
    public async Task AddSubscriptionListAsync(string name, string url, CancellationToken ct = default)
    {
        name = name.Trim();
        url = url.Trim();
        if (string.IsNullOrEmpty(url)) return;

        // Auto-convert GitHub blob to raw URL
        if (url.Contains("github.com", StringComparison.OrdinalIgnoreCase) && url.Contains("/blob/", StringComparison.OrdinalIgnoreCase))
        {
            url = url.Replace("github.com", "raw.githubusercontent.com", StringComparison.OrdinalIgnoreCase)
                     .Replace("/blob/", "/", StringComparison.OrdinalIgnoreCase);
        }

        if (string.IsNullOrEmpty(name))
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
                name = Path.GetFileNameWithoutExtension(uri.LocalPath);
            if (string.IsNullOrWhiteSpace(name)) name = "Custom Blocklist";
        }

        var lists = new List<BlocklistSource>(Settings.Lists);
        lists.RemoveAll(l => string.Equals(l.Url, url, StringComparison.OrdinalIgnoreCase));
        lists.Add(new BlocklistSource(name, url, Enabled: true));

        Settings.Lists = lists;
        _store.Save(Settings);

        await UpdateListsAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Unsubscribes from a blocklist URL and reloads active rules.</summary>
    public async Task RemoveSubscriptionListAsync(string url, CancellationToken ct = default)
    {
        var lists = new List<BlocklistSource>(Settings.Lists);
        lists.RemoveAll(l => string.Equals(l.Url, url, StringComparison.OrdinalIgnoreCase));

        Settings.Lists = lists;
        _store.Save(Settings);

        await Task.Run(ReloadFilter, ct).ConfigureAwait(false);
        Cache.Clear();
    }

    // ---- PC Custom Rules (stored in dns-settings.json) -------------------------------------

    /// <summary>Adds a domain to your PC allow list (and removes it from your PC block list). Takes effect immediately.</summary>
    public Task AllowDomainAsync(string domain) => ChangeRuleAsync(domain, allow: true);

    /// <summary>Adds a domain to your PC block list (and removes it from your PC allow list). Takes effect immediately.</summary>
    public Task BlockDomainAsync(string domain) => ChangeRuleAsync(domain, allow: false);

    private async Task ChangeRuleAsync(string domain, bool allow)
    {
        string d = DomainFilter.Normalize(domain);
        if (d.Length == 0) return;

        var add = allow ? Settings.CustomAllow : Settings.CustomBlock;
        var remove = allow ? Settings.CustomBlock : Settings.CustomAllow;

        remove.RemoveAll(r => string.Equals(r.Trim(), d, StringComparison.OrdinalIgnoreCase));
        if (!add.Any(r => string.Equals(r.Trim(), d, StringComparison.OrdinalIgnoreCase))) add.Add(d);

        _store.Save(Settings);
        await Task.Run(RefreshCustomFilters).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>
    /// Imports a batch of rules (from hosts files, domain lists, or text lines) into either the PC custom block list or PC custom allow list.
    /// </summary>
    public async Task<(int Added, int Skipped)> ImportCustomRulesAsync(IEnumerable<string> rawLines, bool allow, CancellationToken ct = default)
    {
        var parsedRules = DomainFilter.ExtractRulesFromLines(rawLines);
        if (parsedRules.Count == 0) return (0, 0);

        var targetList = allow ? Settings.CustomAllow : Settings.CustomBlock;
        var opposingList = allow ? Settings.CustomBlock : Settings.CustomAllow;

        var existingTarget = new HashSet<string>(targetList, StringComparer.OrdinalIgnoreCase);
        var toAdd = new List<string>();
        int skipped = 0;

        foreach (var rule in parsedRules)
        {
            if (existingTarget.Contains(rule))
            {
                skipped++;
            }
            else
            {
                toAdd.Add(rule);
                existingTarget.Add(rule);
            }
        }

        if (toAdd.Count == 0) return (0, skipped);

        var toAddSet = new HashSet<string>(toAdd, StringComparer.OrdinalIgnoreCase);
        opposingList.RemoveAll(r => toAddSet.Contains(r.Trim()));

        targetList.AddRange(toAdd);

        _store.Save(Settings);
        await Task.Run(RefreshCustomFilters, ct).ConfigureAwait(false);
        Cache.Clear();

        return (toAdd.Count, skipped);
    }

    /// <summary>Removes a domain from both PC custom block and PC custom allow lists. Takes effect immediately.</summary>
    public async Task RemoveCustomRuleAsync(string domain)
    {
        string d = DomainFilter.Normalize(domain);
        if (d.Length == 0) return;

        Settings.CustomBlock.RemoveAll(r => string.Equals(r.Trim(), d, StringComparison.OrdinalIgnoreCase) || DomainFilter.MatchesCustomRule(r, d));
        Settings.CustomAllow.RemoveAll(r => string.Equals(r.Trim(), d, StringComparison.OrdinalIgnoreCase) || DomainFilter.MatchesCustomRule(r, d));

        _store.Save(Settings);
        await Task.Run(RefreshCustomFilters).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>Removes a batch of domains from both PC custom block and PC custom allow lists in a single transaction.</summary>
    public async Task RemoveCustomRulesBatchAsync(IEnumerable<string> domains, CancellationToken ct = default)
    {
        var toRemoveSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in domains)
        {
            string norm = DomainFilter.Normalize(d);
            if (norm.Length > 0) toRemoveSet.Add(norm);
        }

        if (toRemoveSet.Count == 0) return;

        Settings.CustomBlock.RemoveAll(r => toRemoveSet.Contains(DomainFilter.Normalize(r)));
        Settings.CustomAllow.RemoveAll(r => toRemoveSet.Contains(DomainFilter.Normalize(r)));

        _store.Save(Settings);
        await Task.Run(RefreshCustomFilters, ct).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>Clears the entire PC custom allow list or PC custom block list in a single transaction.</summary>
    public async Task ClearCustomRulesAsync(bool allow, CancellationToken ct = default)
    {
        if (allow)
        {
            if (Settings.CustomAllow.Count == 0) return;
            Settings.CustomAllow.Clear();
        }
        else
        {
            if (Settings.CustomBlock.Count == 0) return;
            Settings.CustomBlock.Clear();
        }

        _store.Save(Settings);
        await Task.Run(RefreshCustomFilters, ct).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>Moves a collection of PC rules from one list to the other (e.g. from Blocklist to Whitelist).</summary>
    public async Task MoveRulesAsync(IEnumerable<string> domains, bool toAllow, CancellationToken ct = default)
    {
        var rules = domains.Select(DomainFilter.Normalize).Where(d => d.Length > 0).ToList();
        if (rules.Count == 0) return;

        var targetList = toAllow ? Settings.CustomAllow : Settings.CustomBlock;
        var opposingList = toAllow ? Settings.CustomBlock : Settings.CustomAllow;

        var targetSet = new HashSet<string>(targetList, StringComparer.OrdinalIgnoreCase);
        var moveSet = new HashSet<string>(rules, StringComparer.OrdinalIgnoreCase);

        opposingList.RemoveAll(r => moveSet.Contains(DomainFilter.Normalize(r)));
        foreach (var r in rules)
        {
            if (targetSet.Add(r))
            {
                targetList.Add(r);
            }
        }

        _store.Save(Settings);
        await Task.Run(RefreshCustomFilters, ct).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>Checks whether the domain matches any user's PC custom block rule.</summary>
    public bool IsCustomBlocked(string domain) =>
        Settings.CustomBlock.Any(r => DomainFilter.MatchesCustomRule(r, domain));

    /// <summary>Checks whether the domain matches any user's PC custom allow rule.</summary>
    public bool IsCustomAllowed(string domain) =>
        Settings.CustomAllow.Any(r => DomainFilter.MatchesCustomRule(r, domain));

    // ---- Phone & Smart TV Custom Rules (stored in tv-mobile-rules.json) --------------------

    /// <summary>Adds a domain to the Phone &amp; TV allow list (and removes it from the Phone &amp; TV block list). Stored in tv-mobile-rules.json.</summary>
    public Task AllowTvMobileDomainAsync(string domain) => ChangeTvMobileRuleAsync(domain, allow: true);

    /// <summary>Adds a domain to the Phone &amp; TV block list (and removes it from the Phone &amp; TV allow list). Stored in tv-mobile-rules.json.</summary>
    public Task BlockTvMobileDomainAsync(string domain) => ChangeTvMobileRuleAsync(domain, allow: false);

    private async Task ChangeTvMobileRuleAsync(string domain, bool allow)
    {
        string d = DomainFilter.Normalize(domain);
        if (d.Length == 0) return;

        var add = allow ? TvMobileRules.CustomAllow : TvMobileRules.CustomBlock;
        var remove = allow ? TvMobileRules.CustomBlock : TvMobileRules.CustomAllow;

        remove.RemoveAll(r => string.Equals(r.Trim(), d, StringComparison.OrdinalIgnoreCase));
        if (!add.Any(r => string.Equals(r.Trim(), d, StringComparison.OrdinalIgnoreCase))) add.Add(d);

        // If whitelisting on Phone/TV, also ensure group presets don't keep blocking it
        if (allow)
        {
            bool groupModified = false;
            foreach (var grp in Settings.ClientGroups)
            {
                if (grp.CustomBlock.RemoveAll(r => string.Equals(r.Trim(), d, StringComparison.OrdinalIgnoreCase)) > 0)
                {
                    groupModified = true;
                }
            }
            if (groupModified) _store.Save(Settings);
        }

        _tvMobileStore.Save(TvMobileRules);
        await Task.Run(RefreshCustomFilters).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>Removes a domain from both Phone &amp; TV custom block and allow lists in tv-mobile-rules.json.</summary>
    public async Task RemoveTvMobileCustomRuleAsync(string domain)
    {
        string d = DomainFilter.Normalize(domain);
        if (d.Length == 0) return;

        TvMobileRules.CustomBlock.RemoveAll(r => string.Equals(r.Trim(), d, StringComparison.OrdinalIgnoreCase) || DomainFilter.MatchesCustomRule(r, d));
        TvMobileRules.CustomAllow.RemoveAll(r => string.Equals(r.Trim(), d, StringComparison.OrdinalIgnoreCase) || DomainFilter.MatchesCustomRule(r, d));

        _tvMobileStore.Save(TvMobileRules);
        await Task.Run(RefreshCustomFilters).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>Removes a batch of domains from both Phone &amp; TV custom block and allow lists in tv-mobile-rules.json.</summary>
    public async Task RemoveTvMobileCustomRulesBatchAsync(IEnumerable<string> domains, CancellationToken ct = default)
    {
        var toRemoveSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in domains)
        {
            string norm = DomainFilter.Normalize(d);
            if (norm.Length > 0) toRemoveSet.Add(norm);
        }

        if (toRemoveSet.Count == 0) return;

        TvMobileRules.CustomBlock.RemoveAll(r => toRemoveSet.Contains(DomainFilter.Normalize(r)));
        TvMobileRules.CustomAllow.RemoveAll(r => toRemoveSet.Contains(DomainFilter.Normalize(r)));

        _tvMobileStore.Save(TvMobileRules);
        await Task.Run(RefreshCustomFilters, ct).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>Clears the entire Phone &amp; TV custom allow list or custom block list in tv-mobile-rules.json.</summary>
    public async Task ClearTvMobileCustomRulesAsync(bool allow, CancellationToken ct = default)
    {
        if (allow)
        {
            if (TvMobileRules.CustomAllow.Count == 0) return;
            TvMobileRules.CustomAllow.Clear();
        }
        else
        {
            if (TvMobileRules.CustomBlock.Count == 0) return;
            TvMobileRules.CustomBlock.Clear();
        }

        _tvMobileStore.Save(TvMobileRules);
        await Task.Run(RefreshCustomFilters, ct).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>Moves a collection of Phone &amp; TV rules between Blocklist and Whitelist in tv-mobile-rules.json.</summary>
    public async Task MoveTvMobileRulesAsync(IEnumerable<string> domains, bool toAllow, CancellationToken ct = default)
    {
        var rules = domains.Select(DomainFilter.Normalize).Where(d => d.Length > 0).ToList();
        if (rules.Count == 0) return;

        var targetList = toAllow ? TvMobileRules.CustomAllow : TvMobileRules.CustomBlock;
        var opposingList = toAllow ? TvMobileRules.CustomBlock : TvMobileRules.CustomAllow;

        var targetSet = new HashSet<string>(targetList, StringComparer.OrdinalIgnoreCase);
        var moveSet = new HashSet<string>(rules, StringComparer.OrdinalIgnoreCase);

        opposingList.RemoveAll(r => moveSet.Contains(DomainFilter.Normalize(r)));
        foreach (var r in rules)
        {
            if (targetSet.Add(r))
            {
                targetList.Add(r);
            }
        }

        _tvMobileStore.Save(TvMobileRules);
        await Task.Run(RefreshCustomFilters, ct).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>Imports a batch of rules into the Phone &amp; TV custom blocklist or whitelist (tv-mobile-rules.json).</summary>
    public async Task<(int Added, int Skipped)> ImportTvMobileCustomRulesAsync(IEnumerable<string> rawLines, bool allow, CancellationToken ct = default)
    {
        var parsedRules = DomainFilter.ExtractRulesFromLines(rawLines);
        if (parsedRules.Count == 0) return (0, 0);

        var targetList = allow ? TvMobileRules.CustomAllow : TvMobileRules.CustomBlock;
        var opposingList = allow ? TvMobileRules.CustomBlock : TvMobileRules.CustomAllow;

        var existingTarget = new HashSet<string>(targetList, StringComparer.OrdinalIgnoreCase);
        var toAdd = new List<string>();
        int skipped = 0;

        foreach (var rule in parsedRules)
        {
            if (existingTarget.Contains(rule))
            {
                skipped++;
            }
            else
            {
                toAdd.Add(rule);
                existingTarget.Add(rule);
            }
        }

        if (toAdd.Count == 0) return (0, skipped);

        var toAddSet = new HashSet<string>(toAdd, StringComparer.OrdinalIgnoreCase);
        opposingList.RemoveAll(r => toAddSet.Contains(r.Trim()));

        targetList.AddRange(toAdd);

        _tvMobileStore.Save(TvMobileRules);
        await Task.Run(RefreshCustomFilters, ct).ConfigureAwait(false);
        Cache.Clear();

        return (toAdd.Count, skipped);
    }

    /// <summary>Moves or copies selected custom rules between the PC list (dns-settings.json) and the Phone &amp; TV list (tv-mobile-rules.json).</summary>
    public async Task MoveRulesBetweenScopesAsync(
        IEnumerable<string> domains,
        bool fromTvMobileToPc,
        bool isAllowList,
        bool removeFromSource = true,
        CancellationToken ct = default)
    {
        var rules = domains.Select(DomainFilter.Normalize).Where(d => d.Length > 0).ToList();
        if (rules.Count == 0) return;

        var sourceList = fromTvMobileToPc
            ? (isAllowList ? TvMobileRules.CustomAllow : TvMobileRules.CustomBlock)
            : (isAllowList ? Settings.CustomAllow : Settings.CustomBlock);

        var destList = fromTvMobileToPc
            ? (isAllowList ? Settings.CustomAllow : Settings.CustomBlock)
            : (isAllowList ? TvMobileRules.CustomAllow : TvMobileRules.CustomBlock);

        var destOpposingList = fromTvMobileToPc
            ? (isAllowList ? Settings.CustomBlock : Settings.CustomAllow)
            : (isAllowList ? TvMobileRules.CustomBlock : TvMobileRules.CustomAllow);

        var destSet = new HashSet<string>(destList, StringComparer.OrdinalIgnoreCase);
        var moveSet = new HashSet<string>(rules, StringComparer.OrdinalIgnoreCase);

        if (removeFromSource)
        {
            sourceList.RemoveAll(r => moveSet.Contains(DomainFilter.Normalize(r)));
        }

        destOpposingList.RemoveAll(r => moveSet.Contains(DomainFilter.Normalize(r)));
        foreach (var r in rules)
        {
            if (destSet.Add(r))
            {
                destList.Add(r);
            }
        }

        _store.Save(Settings);
        _tvMobileStore.Save(TvMobileRules);
        await Task.Run(RefreshCustomFilters, ct).ConfigureAwait(false);
        Cache.Clear();
    }

    /// <summary>Checks whether the domain matches any Phone &amp; TV custom block rule in tv-mobile-rules.json.</summary>
    public bool IsTvMobileCustomBlocked(string domain) =>
        TvMobileRules.CustomBlock.Any(r => DomainFilter.MatchesCustomRule(r, domain));

    /// <summary>Checks whether the domain matches any Phone &amp; TV custom allow rule in tv-mobile-rules.json.</summary>
    public bool IsTvMobileCustomAllowed(string domain) =>
        TvMobileRules.CustomAllow.Any(r => DomainFilter.MatchesCustomRule(r, domain));

    // ---- Diagnostics & History -------------------------------------------------------------

    /// <summary>
    /// Sends real queries to the running server on its configured port: one normal name, and one name the filter blocks.
    /// Works on any port (Windows' nslookup only uses port 53).
    /// </summary>
    public async Task<DnsSelfTestResult> SelfTestAsync(CancellationToken ct = default)
    {
        var endpoint = LocalEndPoint;
        if (endpoint is null)
            return new DnsSelfTestResult(false, new[] { "The DNS server is not running. Press 'Start DNS server' first." });

        return await DnsSelfTest.RunAsync(endpoint, BlockedSample(), ct: ct).ConfigureAwait(false);
    }

    /// <summary>A name the current filter blocks (for the self-test), or null when nothing is blocked yet.</summary>
    public string? BlockedSample()
    {
        var filter = _filter;
        foreach (var candidate in new[] { "doubleclick.net", "googleadservices.com", "ads.example.com" })
            if (filter.Decide(candidate).Action == FilterAction.Blocked) return candidate;

        foreach (var rule in Settings.CustomBlock)
        {
            string r = rule.Trim();
            if (r.Length == 0 || r.StartsWith('/') || r.StartsWith('#')) continue;   // regex rules have no fixed name to ask for
            if (r.StartsWith("*.", StringComparison.Ordinal)) r = "test." + r[2..];
            string d = DomainFilter.Normalize(r);
            if (d.Length > 0 && filter.Decide(d).Action == FilterAction.Blocked) return d;
        }
        return null;
    }

    /// <summary>Returns the PC filter's decision for a domain without sending any query.</summary>
    public FilterDecision Decide(string domain) => _filter.Decide(DomainFilter.Normalize(domain));

    /// <summary>Returns the Phone &amp; TV filter's decision for a domain without sending any query.</summary>
    public FilterDecision DecideTvMobile(string domain) => _tvMobileFilter.Decide(DomainFilter.Normalize(domain));

    /// <summary>Says what the filter would do with a domain, without sending any query.</summary>
    public string Check(string domain)
    {
        string d = DomainFilter.Normalize(domain);
        if (d.Length == 0) return "";

        var decision = _filter.Decide(d);
        return decision.Action switch
        {
            FilterAction.Blocked => $"{d} is BLOCKED ({decision.Reason}).",
            FilterAction.Allowed => $"{d} is allowed ({decision.Reason}).",
            _ => _filter.BlockedDomainCount == 0 && Settings.CustomBlock.Count == 0
                ? $"{d} is not blocked. (No block list is loaded yet: use 'Update block lists'.)"
                : $"{d} is not on any block list.",
        };
    }

    /// <summary>Direct access to the SQLite DNS history database.</summary>
    public DnsHistoryDatabase HistoryDb => _historyDb;

    /// <summary>Returns live health and latency metrics for configured upstream resolvers.</summary>
    public IReadOnlyList<UpstreamStatus> GetUpstreamStatuses() =>
        _compositeResolver?.GetStatuses() ?? Array.Empty<UpstreamStatus>();

    /// <summary>Loads recent historical queries from the persistent SQLite database.</summary>
    public Task<IReadOnlyList<DnsLogEntry>> LoadRecentHistoryAsync(int limit = 500, CancellationToken ct = default) =>
        _historyDb.GetRecentEntriesAsync(limit, ct);

    /// <summary>Loads recent historical LAN (non-loopback) queries from the persistent SQLite database.</summary>
    public Task<IReadOnlyList<DnsLogEntry>> LoadRecentLanHistoryAsync(int limit = 1000, CancellationToken ct = default) =>
        _historyDb.GetRecentLanEntriesAsync(limit, ct);

    /// <summary>Returns the client-group-aware filter decision for a domain (PC vs. Phone/TV separated).</summary>
    public FilterDecision DecideForClient(IPAddress clientIp, string domain)
    {
        if (IsBlockingPaused)
            return new FilterDecision(FilterAction.Allowed, "blocking paused");

        if (_server is not null)
            return _server.DecideForClient(clientIp, domain);

        var targetIp = clientIp.IsIPv4MappedToIPv6 ? clientIp.MapToIPv4() : clientIp;
        if (IPAddress.IsLoopback(targetIp))
            return Decide(domain);

        return DecideTvMobile(domain);
    }

    /// <summary>Records an activity entry from the Proxy Hub or L3 Gateway Router into in-memory counters and SQLite history.</summary>
    public void RecordExternalActivity(DnsLogEntry entry)
    {
        Activity.Add(entry);
        _historyDb.Enqueue(entry, Settings.AnonymizeClientIps, Settings.DoNotStoreDomains);
    }

    /// <summary>Exports query history to CSV.</summary>
    public Task ExportHistoryCsvAsync(TextWriter writer, DateTimeOffset? from = null, DateTimeOffset? to = null, CancellationToken ct = default) =>
        _historyDb.ExportCsvAsync(writer, from, to, ct);

    /// <summary>Prunes historical query log entries older than the specified number of days.</summary>
    public Task<int> PruneHistoryAsync(int days, CancellationToken ct = default) =>
        _historyDb.PruneOlderThanDaysAsync(days, ct);

    /// <summary>Clears all DNS query history from SQLite database and resets in-memory activity counters.</summary>
    public async Task ClearHistoryAsync(CancellationToken ct = default)
    {
        await _historyDb.ClearAllAsync(ct).ConfigureAwait(false);
        Activity.Reset();
    }
}
