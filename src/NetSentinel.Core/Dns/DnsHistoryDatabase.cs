using System.Globalization;
using System.Net;
using System.Text;
using System.Threading.Channels;
using Microsoft.Data.Sqlite;

namespace NetSentinel.Sinkhole;

/// <summary>
/// Persistent SQLite storage for DNS queries with high-throughput batched writes,
/// configurable retention pruning, privacy masking, and CSV export.
/// </summary>
public sealed class DnsHistoryDatabase : IDisposable
{
    private readonly string _connectionString;
    private readonly string _dbPath;
    private readonly Channel<DnsLogEntry> _channel;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _writerTask;
    private bool _disposed;

    public string DatabasePath => _dbPath;

    public static string DefaultPath => NetSentinel.Core.EngineStoragePaths.DnsHistoryPath;

    public DnsHistoryDatabase(string dbPath)
    {
        _dbPath = dbPath;
        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString();

        InitializeDatabase();

        _channel = Channel.CreateBounded<DnsLogEntry>(new BoundedChannelOptions(50_000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true
        });

        _writerTask = Task.Run(WriterLoopAsync);
    }

    private void InitializeDatabase()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                client TEXT NOT NULL,
                domain TEXT NOT NULL,
                qtype TEXT NOT NULL,
                outcome TEXT NOT NULL,
                detail TEXT,
                ms INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
            CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain);
        ";
        cmd.ExecuteNonQuery();
    }

    public void Enqueue(DnsLogEntry entry, bool anonymizeIps = false, bool redactDomains = false)
    {
        if (_disposed) return;

        string client = anonymizeIps ? AnonymizeClient(entry.Client) : entry.Client;
        string domain = redactDomains ? "[redacted]" : entry.Domain;

        var sanitized = new DnsLogEntry(
            entry.Time,
            client,
            domain,
            entry.Type,
            entry.Outcome,
            entry.Detail,
            entry.Milliseconds
        );

        _channel.Writer.TryWrite(sanitized);
    }

    private static string AnonymizeClient(string client)
    {
        if (IPAddress.TryParse(client, out var ip))
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();
                bytes[3] = 0;
                return new IPAddress(bytes).ToString();
            }
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var bytes = ip.GetAddressBytes();
                for (int i = 8; i < 16; i++) bytes[i] = 0;
                return new IPAddress(bytes).ToString();
            }
        }
        return client;
    }

    private async Task WriterLoopAsync()
    {
        var batch = new List<DnsLogEntry>(100);
        var reader = _channel.Reader;
        var token = _cts.Token;

        try
        {
            while (await reader.WaitToReadAsync(token).ConfigureAwait(false))
            {
                batch.Clear();
                while (batch.Count < 100 && reader.TryRead(out var item))
                {
                    batch.Add(item);
                }

                if (batch.Count > 0)
                {
                    WriteBatch(batch);
                }

                // Brief pause to batch rapidly arriving queries
                await Task.Delay(100, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Drain remaining
            while (reader.TryRead(out var item))
            {
                batch.Add(item);
                if (batch.Count >= 100)
                {
                    WriteBatch(batch);
                    batch.Clear();
                }
            }
            if (batch.Count > 0)
            {
                WriteBatch(batch);
            }
        }
        catch (Exception)
        {
            // Logging errors should not crash the app
        }
    }

    private void WriteBatch(List<DnsLogEntry> batch)
    {
        try
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();

            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO queries (ts, client, domain, qtype, outcome, detail, ms)
                VALUES (@ts, @client, @domain, @qtype, @outcome, @detail, @ms)
            ";

            var pTs = cmd.Parameters.Add("@ts", SqliteType.Text);
            var pClient = cmd.Parameters.Add("@client", SqliteType.Text);
            var pDomain = cmd.Parameters.Add("@domain", SqliteType.Text);
            var pQtype = cmd.Parameters.Add("@qtype", SqliteType.Text);
            var pOutcome = cmd.Parameters.Add("@outcome", SqliteType.Text);
            var pDetail = cmd.Parameters.Add("@detail", SqliteType.Text);
            var pMs = cmd.Parameters.Add("@ms", SqliteType.Integer);

            foreach (var item in batch)
            {
                pTs.Value = item.Time.ToString("o", CultureInfo.InvariantCulture);
                pClient.Value = item.Client;
                pDomain.Value = item.Domain;
                pQtype.Value = item.Type;
                pOutcome.Value = item.Outcome.ToString();
                pDetail.Value = (object?)item.Detail ?? DBNull.Value;
                pMs.Value = item.Milliseconds;

                cmd.ExecuteNonQuery();
            }

            tx.Commit();
        }
        catch (Exception)
        {
            // Transient database write error
        }
    }

    public async Task<int> PruneOlderThanDaysAsync(int days, CancellationToken ct = default)
    {
        if (days <= 0) return 0;

        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM queries WHERE ts < datetime('now', '-' || @days || ' days');";
        cmd.Parameters.AddWithValue("@days", days);

        return await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<DnsLogEntry>> GetRecentEntriesAsync(int limit = 500, CancellationToken ct = default)
    {
        var list = new List<DnsLogEntry>();

        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT ts, client, domain, qtype, outcome, detail, ms
            FROM queries
            ORDER BY id DESC
            LIMIT @limit;
        ";
        cmd.Parameters.AddWithValue("@limit", limit);

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var ts = DateTimeOffset.TryParse(reader.GetString(0), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dt)
                ? dt : DateTimeOffset.Now;
            string client = reader.GetString(1);
            string domain = reader.GetString(2);
            string type = reader.GetString(3);
            string outcomeStr = reader.GetString(4);
            string? detail = reader.IsDBNull(5) ? null : reader.GetString(5);
            int ms = reader.GetInt32(6);

            var outcome = Enum.TryParse<DnsOutcome>(outcomeStr, out var o) ? o : DnsOutcome.Forwarded;
            list.Add(new DnsLogEntry(ts, client, domain, type, outcome, detail, ms));
        }

        return list;
    }

    public async Task ExportCsvAsync(TextWriter writer, DateTimeOffset? from = null, DateTimeOffset? to = null, CancellationToken ct = default)
    {
        await writer.WriteLineAsync("Timestamp,Client,Domain,Type,Outcome,Detail,DurationMs").ConfigureAwait(false);

        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        var sb = new StringBuilder(@"
            SELECT ts, client, domain, qtype, outcome, detail, ms
            FROM queries
            WHERE 1=1
        ");

        if (from.HasValue)
        {
            sb.Append(" AND ts >= @from");
            cmd.Parameters.AddWithValue("@from", from.Value.ToString("o", CultureInfo.InvariantCulture));
        }
        if (to.HasValue)
        {
            sb.Append(" AND ts <= @to");
            cmd.Parameters.AddWithValue("@to", to.Value.ToString("o", CultureInfo.InvariantCulture));
        }
        sb.Append(" ORDER BY id ASC");
        cmd.CommandText = sb.ToString();

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            string ts = reader.GetString(0);
            string client = EscapeCsv(reader.GetString(1));
            string domain = EscapeCsv(reader.GetString(2));
            string type = EscapeCsv(reader.GetString(3));
            string outcome = EscapeCsv(reader.GetString(4));
            string detail = reader.IsDBNull(5) ? "" : EscapeCsv(reader.GetString(5));
            int ms = reader.GetInt32(6);

            await writer.WriteLineAsync($"{ts},{client},{domain},{type},{outcome},{detail},{ms}").ConfigureAwait(false);
        }
    }

    private static string EscapeCsv(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
        {
            return $"\"{value.Replace("\"", "\"\"")}\"";
        }
        return value;
    }

    public void Flush()
    {
        _cts.Cancel();
        try { _writerTask.Wait(TimeSpan.FromSeconds(2)); } catch { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        try { _writerTask.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cts.Dispose();
    }
}
