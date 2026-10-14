using System.Threading.Channels;
using Microsoft.Data.Sqlite;

namespace SpectraNetworkManager.Core;

public sealed record ConnectionHistoryRecord(
    string Program,
    string Remote,
    int Port,
    string Proto,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen);

public sealed record BandwidthMinuteRecord(
    DateTimeOffset Minute,
    string Program,
    long BytesIn,
    long BytesOut);

public sealed record ProgramTrafficSummary(
    string Program,
    long TotalBytesIn,
    long TotalBytesOut,
    DateTimeOffset LastActivity);

/// <summary>
/// High-performance SQLite database for recording connection history and per-process bandwidth.
/// Uses WAL mode and asynchronous batch writing via System.Threading.Channels.
/// </summary>
public sealed class NetworkHistoryDatabase : IAsyncDisposable, IDisposable
{
    private readonly string _dbPath;
    private readonly Channel<ConnectionHistoryRecord> _connChannel = Channel.CreateBounded<ConnectionHistoryRecord>(new BoundedChannelOptions(10000)
    {
        FullMode = BoundedChannelFullMode.DropOldest
    });
    private readonly Channel<BandwidthMinuteRecord> _bwChannel = Channel.CreateBounded<BandwidthMinuteRecord>(new BoundedChannelOptions(10000)
    {
        FullMode = BoundedChannelFullMode.DropOldest
    });

    private readonly CancellationTokenSource _cts = new();
    private readonly Task _writerTask;
    private bool _disposed;

    public NetworkHistoryDatabase(string? dbPath = null)
    {
        _dbPath = dbPath ?? EngineStoragePaths.NetworkHistoryPath;
        var dir = Path.GetDirectoryName(_dbPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            try { Directory.CreateDirectory(dir); } catch { }
        }

        InitializeDatabase();
        _writerTask = Task.Run(BatchWriterLoopAsync);
    }

    private void InitializeDatabase()
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connections_seen (
                program TEXT NOT NULL,
                remote TEXT NOT NULL,
                port INTEGER NOT NULL,
                proto TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (program, remote, port, proto)
            );
            CREATE INDEX IF NOT EXISTS idx_conn_last_seen ON connections_seen(last_seen);

            CREATE TABLE IF NOT EXISTS bandwidth_minute (
                minute INTEGER NOT NULL,
                program TEXT NOT NULL,
                bytes_in INTEGER NOT NULL,
                bytes_out INTEGER NOT NULL,
                PRIMARY KEY (minute, program)
            );
            CREATE INDEX IF NOT EXISTS idx_bw_minute ON bandwidth_minute(minute);
        ";
        cmd.ExecuteNonQuery();
    }

    public void RecordConnection(string program, string remote, int port, string proto, DateTimeOffset time)
    {
        if (_disposed) return;
        _connChannel.Writer.TryWrite(new ConnectionHistoryRecord(program, remote, port, proto, time, time));
    }

    public void RecordBandwidth(DateTimeOffset minute, string program, long bytesIn, long bytesOut)
    {
        if (_disposed || (bytesIn == 0 && bytesOut == 0)) return;
        _bwChannel.Writer.TryWrite(new BandwidthMinuteRecord(minute, program, bytesIn, bytesOut));
    }

    public async Task<IReadOnlyList<ConnectionHistoryRecord>> GetRecentConnectionsAsync(int limit = 200)
    {
        var list = new List<ConnectionHistoryRecord>();
        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync().ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT program, remote, port, proto, first_seen, last_seen
            FROM connections_seen
            ORDER BY last_seen DESC
            LIMIT @limit;
        ";
        cmd.Parameters.AddWithValue("@limit", limit);

        await using var reader = await cmd.ExecuteReaderAsync().ConfigureAwait(false);
        while (await reader.ReadAsync().ConfigureAwait(false))
        {
            list.Add(new ConnectionHistoryRecord(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetInt32(2),
                reader.GetString(3),
                DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(4)),
                DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(5))));
        }

        return list;
    }

    public async Task<IReadOnlyList<ProgramTrafficSummary>> GetTopTalkersAsync(TimeSpan window)
    {
        var list = new List<ProgramTrafficSummary>();
        long cutoff = DateTimeOffset.UtcNow.Subtract(window).ToUnixTimeSeconds();

        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync().ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT program, SUM(bytes_in) AS total_in, SUM(bytes_out) AS total_out, MAX(minute) AS last_min
            FROM bandwidth_minute
            WHERE minute >= @cutoff
            GROUP BY program
            ORDER BY (SUM(bytes_in) + SUM(bytes_out)) DESC
            LIMIT 50;
        ";
        cmd.Parameters.AddWithValue("@cutoff", cutoff);

        await using var reader = await cmd.ExecuteReaderAsync().ConfigureAwait(false);
        while (await reader.ReadAsync().ConfigureAwait(false))
        {
            list.Add(new ProgramTrafficSummary(
                reader.GetString(0),
                reader.GetInt64(1),
                reader.GetInt64(2),
                DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(3))));
        }

        return list;
    }

    public async Task PruneOlderThanDaysAsync(int days)
    {
        if (days <= 0) return;
        long cutoff = DateTimeOffset.UtcNow.AddDays(-days).ToUnixTimeSeconds();

        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync().ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            DELETE FROM connections_seen WHERE last_seen < @cutoff;
            DELETE FROM bandwidth_minute WHERE minute < @cutoff;
        ";
        cmd.Parameters.AddWithValue("@cutoff", cutoff);
        await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
    }

    private async Task BatchWriterLoopAsync()
    {
        var connBatch = new List<ConnectionHistoryRecord>(256);
        var bwBatch = new List<BandwidthMinuteRecord>(256);

        while (!_cts.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(2000, _cts.Token).ConfigureAwait(false);

                while (_connChannel.Reader.TryRead(out var c))
                {
                    connBatch.Add(c);
                    if (connBatch.Count >= 500) break;
                }

                while (_bwChannel.Reader.TryRead(out var b))
                {
                    bwBatch.Add(b);
                    if (bwBatch.Count >= 500) break;
                }

                if (connBatch.Count > 0 || bwBatch.Count > 0)
                {
                    await FlushBatchAsync(connBatch, bwBatch).ConfigureAwait(false);
                    connBatch.Clear();
                    bwBatch.Clear();
                }
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested)
            {
                break;
            }
            catch (Exception)
            {
                // Continue resiliently
            }
        }

        // Final drain
        while (_connChannel.Reader.TryRead(out var c)) connBatch.Add(c);
        while (_bwChannel.Reader.TryRead(out var b)) bwBatch.Add(b);
        if (connBatch.Count > 0 || bwBatch.Count > 0)
        {
            try { await FlushBatchAsync(connBatch, bwBatch).ConfigureAwait(false); } catch { }
        }
    }

    private async Task FlushBatchAsync(List<ConnectionHistoryRecord> conns, List<BandwidthMinuteRecord> bws)
    {
        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync().ConfigureAwait(false);
        using var trans = conn.BeginTransaction();

        if (conns.Count > 0)
        {
            await using var cmd = conn.CreateCommand();
            cmd.Transaction = trans;
            cmd.CommandText = @"
                INSERT INTO connections_seen(program, remote, port, proto, first_seen, last_seen)
                VALUES(@prog, @rem, @port, @proto, @first, @last)
                ON CONFLICT(program, remote, port, proto) DO UPDATE SET
                    last_seen = excluded.last_seen;
            ";
            var pProg = cmd.Parameters.Add("@prog", SqliteType.Text);
            var pRem = cmd.Parameters.Add("@rem", SqliteType.Text);
            var pPort = cmd.Parameters.Add("@port", SqliteType.Integer);
            var pProto = cmd.Parameters.Add("@proto", SqliteType.Text);
            var pFirst = cmd.Parameters.Add("@first", SqliteType.Integer);
            var pLast = cmd.Parameters.Add("@last", SqliteType.Integer);

            foreach (var c in conns)
            {
                pProg.Value = c.Program;
                pRem.Value = c.Remote;
                pPort.Value = c.Port;
                pProto.Value = c.Proto;
                pFirst.Value = c.FirstSeen.ToUnixTimeSeconds();
                pLast.Value = c.LastSeen.ToUnixTimeSeconds();
                await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
            }
        }

        if (bws.Count > 0)
        {
            await using var cmd = conn.CreateCommand();
            cmd.Transaction = trans;
            cmd.CommandText = @"
                INSERT INTO bandwidth_minute(minute, program, bytes_in, bytes_out)
                VALUES(@min, @prog, @bin, @bout)
                ON CONFLICT(minute, program) DO UPDATE SET
                    bytes_in = bytes_in + excluded.bytes_in,
                    bytes_out = bytes_out + excluded.bytes_out;
            ";
            var pMin = cmd.Parameters.Add("@min", SqliteType.Integer);
            var pProg = cmd.Parameters.Add("@prog", SqliteType.Text);
            var pBin = cmd.Parameters.Add("@bin", SqliteType.Integer);
            var pBout = cmd.Parameters.Add("@bout", SqliteType.Integer);

            foreach (var b in bws)
            {
                pMin.Value = b.Minute.ToUnixTimeSeconds();
                pProg.Value = b.Program;
                pBin.Value = b.BytesIn;
                pBout.Value = b.BytesOut;
                await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
            }
        }

        await trans.CommitAsync().ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        try { await _writerTask.ConfigureAwait(false); } catch { }
        _cts.Dispose();
    }
}
