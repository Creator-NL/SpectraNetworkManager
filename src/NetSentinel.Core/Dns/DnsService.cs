using System.Net;

namespace NetSentinel.Sinkhole;

/// <summary>
/// Everything the DNS sinkhole needs in one place: settings, block lists, the server, the cache and the activity log.
/// The window talks only to this class.
/// </summary>
public sealed class DnsService : IDisposable
{
    private readonly DnsSettingsStore _store;
    private readonly BlocklistManager _lists;
    private DnsServer? _server;
    private volatile DomainFilter _filter = DomainFilter.Empty;

    public DnsService(string settingsFile, string listsFolder, HttpMessageHandler? handler = null)
    {
        _store = new DnsSettingsStore(settingsFile);
        _lists = new BlocklistManager(listsFolder, handler);
        Settings = _store.Load();
        Cache = new DnsCache(Settings.CacheEntries);
    }

    public static DnsService CreateDefault() => new(DnsSettingsStore.DefaultPath, BlocklistManager.DefaultFolder);

    public DnsSettings Settings { get; private set; }
    public DnsActivity Activity { get; } = new();
    public DnsCache Cache { get; private set; }
    public FilterLoadInfo? FilterInfo { get; private set; }

    public bool IsRunning => _server?.IsRunning == true;
    public IPEndPoint? LocalEndPoint => _server?.LocalEndPoint;
    public int BlockedDomainCount => _filter.BlockedDomainCount;

    public BlocklistManager Lists => _lists;

    /// <summary>Raised for every answered query (on a background thread).</summary>
    public event Action<DnsLogEntry>? Queried;

    /// <summary>Loads the block lists, then starts answering. Throws if the settings are invalid or the port is already in use.</summary>
    public async Task StartAsync()
    {
        if (IsRunning) return;
        if (!Settings.Validate(out string error)) throw new InvalidOperationException(error);

        await Task.Run(ReloadFilter).ConfigureAwait(false);       // load the lists first, so no query slips through unfiltered

        Cache = new DnsCache(Settings.CacheEntries);
        var resolver = new NetworkUpstreamResolver(Settings.UpstreamEndpoints());
        var server = new DnsServer(Settings, () => _filter, resolver, Cache, Activity);
        server.Queried += e => Queried?.Invoke(e);
        server.Start();
        _server = server;
    }

    public void Stop()
    {
        _server?.Dispose();
        _server = null;
    }

    public void Dispose() => Stop();

    private void ReloadFilter()
    {
        var filter = _lists.LoadFilter(Settings, out var info);
        _filter = filter;
        FilterInfo = info;
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

    public async Task<IReadOnlyList<ListUpdateResult>> UpdateListsAsync(CancellationToken ct = default)
    {
        var results = await _lists.UpdateAsync(Settings.Lists, ct).ConfigureAwait(false);
        await Task.Run(ReloadFilter, ct).ConfigureAwait(false);
        Cache.Clear();                                              // answers cached before may now be blocked
        return results;
    }

    /// <summary>Adds a domain to your allow list (and removes it from your block list). Takes effect immediately.</summary>
    public Task AllowDomainAsync(string domain) => ChangeRuleAsync(domain, allow: true);

    /// <summary>Adds a domain to your block list (and removes it from your allow list). Takes effect immediately.</summary>
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
        await Task.Run(ReloadFilter).ConfigureAwait(false);
        Cache.Clear();
    }

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
}
