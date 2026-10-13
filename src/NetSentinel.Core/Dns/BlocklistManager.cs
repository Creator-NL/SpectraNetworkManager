using System.Security.Cryptography;
using System.Text;

namespace NetSentinel.Sinkhole;

public sealed record ListUpdateResult(string Name, bool Ok, int Bytes, string Message);

public sealed record FilterLoadInfo(int BlockedDomains, int AllowedDomains, int Regexes, IReadOnlyList<string> Notes);

/// <summary>Downloads block lists, keeps them on disk and builds the <see cref="DomainFilter"/> from them plus your own rules.</summary>
public sealed class BlocklistManager
{
    private const long MaxListBytes = 100L * 1024 * 1024;

    private readonly string _folder;
    private readonly HttpMessageHandler? _handler;

    public BlocklistManager(string folder, HttpMessageHandler? handler = null)
    {
        _folder = folder;
        _handler = handler;
    }

    public static string DefaultFolder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSentinel", "blocklists");

    private string FileFor(BlocklistSource list)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(list.Url.ToLowerInvariant()));
        string safe = new string(list.Name.Where(char.IsLetterOrDigit).ToArray());
        if (safe.Length > 24) safe = safe[..24];
        return Path.Combine(_folder, $"{safe}-{Convert.ToHexString(hash, 0, 4).ToLowerInvariant()}.txt");
    }

    public DateTimeOffset? LastUpdated(BlocklistSource list)
    {
        string file = FileFor(list);
        return File.Exists(file) ? new DateTimeOffset(File.GetLastWriteTimeUtc(file), TimeSpan.Zero) : null;
    }

    public async Task<IReadOnlyList<ListUpdateResult>> UpdateAsync(IEnumerable<BlocklistSource> lists, CancellationToken ct = default)
    {
        var results = new List<ListUpdateResult>();
        using var client = _handler is null ? new HttpClient() : new HttpClient(_handler, disposeHandler: false);
        client.Timeout = TimeSpan.FromSeconds(90);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("NetSentinel");

        Directory.CreateDirectory(_folder);

        foreach (var list in lists.Where(l => l.Enabled))
        {
            try
            {
                if (!Uri.TryCreate(list.Url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
                {
                    results.Add(new ListUpdateResult(list.Name, false, 0, "The address is not a valid http(s) URL."));
                    continue;
                }

                using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!response.IsSuccessStatusCode)
                {
                    results.Add(new ListUpdateResult(list.Name, false, 0, $"Server answered {(int)response.StatusCode} {response.ReasonPhrase}."));
                    continue;
                }
                if (response.Content.Headers.ContentLength > MaxListBytes)
                {
                    results.Add(new ListUpdateResult(list.Name, false, 0, "The list is larger than 100 MB; skipped."));
                    continue;
                }

                string temp = FileFor(list) + ".tmp";
                long total = 0;
                await using (var source = await response.Content.ReadAsStreamAsync(ct))
                await using (var target = File.Create(temp))
                {
                    var buffer = new byte[81920];
                    int read;
                    while ((read = await source.ReadAsync(buffer, ct)) > 0)
                    {
                        total += read;
                        if (total > MaxListBytes) throw new InvalidDataException("The list is larger than 100 MB.");
                        await target.WriteAsync(buffer.AsMemory(0, read), ct);
                    }
                }

                if (total == 0)
                {
                    File.Delete(temp);
                    results.Add(new ListUpdateResult(list.Name, false, 0, "The server sent an empty list; the old copy was kept."));
                    continue;
                }

                File.Move(temp, FileFor(list), overwrite: true);
                results.Add(new ListUpdateResult(list.Name, true, (int)Math.Min(total, int.MaxValue), "Updated."));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                results.Add(new ListUpdateResult(list.Name, false, 0, "Failed: " + ex.Message + " (the old copy was kept)."));
            }
        }

        return results;
    }

    /// <summary>Builds the filter from the downloaded lists plus your own rules. Lists that were never downloaded are skipped.</summary>
    public DomainFilter LoadFilter(DnsSettings settings, out FilterLoadInfo info)
    {
        var builder = new DomainFilterBuilder();
        var notes = new List<string>();

        foreach (var list in settings.Lists.Where(l => l.Enabled))
        {
            string file = FileFor(list);
            if (!File.Exists(file))
            {
                notes.Add($"'{list.Name}' has not been downloaded yet.");
                continue;
            }

            try
            {
                var stats = builder.AddListText(File.ReadAllText(file));
                notes.Add($"'{list.Name}': {stats.Blocked:N0} blocked, {stats.Allowed:N0} allowed, {stats.Skipped:N0} lines skipped.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                notes.Add($"'{list.Name}' could not be read: {ex.Message}");
            }
        }

        foreach (var rule in settings.CustomBlock) builder.AddCustom(rule, allow: false);
        foreach (var rule in settings.CustomAllow) builder.AddCustom(rule, allow: true);
        notes.AddRange(builder.Warnings);

        var filter = builder.Build();
        info = new FilterLoadInfo(filter.BlockedDomainCount, filter.AllowedDomainCount, filter.RegexCount, notes);
        return filter;
    }
}
