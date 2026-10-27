using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace SpectraNetworkManager.Core.Ai;

public sealed class AiInvestigationDatabase : IDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false
    };

    private readonly string _dbPath;

    public AiInvestigationDatabase(string? dbPath = null)
    {
        _dbPath = dbPath ?? EngineStoragePaths.AiInvestigationsPath;
        var dir = Path.GetDirectoryName(_dbPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            try { Directory.CreateDirectory(dir); } catch { }
        }

        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                target_type TEXT NOT NULL,
                target_identifier TEXT NOT NULL,
                pid INTEGER,
                process_name TEXT NOT NULL,
                verification_level TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                executive_summary TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                is_ai_generated INTEGER NOT NULL,
                model_used TEXT NOT NULL,
                evidence_json TEXT,
                report_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_inv_timestamp ON investigations(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_inv_target ON investigations(target_identifier);
        ";
        cmd.ExecuteNonQuery();
    }

    public async Task SaveInvestigationAsync(InvestigationReport report)
    {
        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync().ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT OR REPLACE INTO investigations (
                id, timestamp, target_type, target_identifier, pid, process_name,
                verification_level, verdict, risk_score, executive_summary,
                recommendation, is_ai_generated, model_used, evidence_json, report_json
            ) VALUES (
                @id, @ts, @tt, @ti, @pid, @pn,
                @vl, @v, @rs, @es,
                @rec, @ai, @mu, @ej, @rj
            );
        ";

        cmd.Parameters.AddWithValue("@id", report.Id);
        cmd.Parameters.AddWithValue("@ts", report.Timestamp.ToUnixTimeSeconds());
        cmd.Parameters.AddWithValue("@tt", report.TargetType);
        cmd.Parameters.AddWithValue("@ti", report.TargetIdentifier);
        cmd.Parameters.AddWithValue("@pid", (object?)report.Pid ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@pn", report.ProcessName);
        cmd.Parameters.AddWithValue("@vl", report.VerificationLevel.ToString());
        cmd.Parameters.AddWithValue("@v", report.Verdict.ToString());
        cmd.Parameters.AddWithValue("@rs", report.RiskScore);
        cmd.Parameters.AddWithValue("@es", report.ExecutiveSummary);
        cmd.Parameters.AddWithValue("@rec", report.Recommendation.ToString());
        cmd.Parameters.AddWithValue("@ai", report.IsAiGenerated ? 1 : 0);
        cmd.Parameters.AddWithValue("@mu", report.ModelUsed);
        cmd.Parameters.AddWithValue("@ej", report.Evidence != null ? JsonSerializer.Serialize(report.Evidence, JsonOpts) : (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@rj", JsonSerializer.Serialize(report, JsonOpts));

        await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<InvestigationReport>> GetRecentInvestigationsAsync(int limit = 100)
    {
        var list = new List<InvestigationReport>();
        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync().ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT report_json FROM investigations
            ORDER BY timestamp DESC
            LIMIT @limit;
        ";
        cmd.Parameters.AddWithValue("@limit", limit);

        await using var reader = await cmd.ExecuteReaderAsync().ConfigureAwait(false);
        while (await reader.ReadAsync().ConfigureAwait(false))
        {
            string json = reader.GetString(0);
            try
            {
                var rep = JsonSerializer.Deserialize<InvestigationReport>(json);
                if (rep != null) list.Add(rep);
            }
            catch { }
        }

        return list;
    }

    public async Task<IReadOnlyList<InvestigationReport>> GetHistoryForTargetAsync(string targetIdentifier)
    {
        var list = new List<InvestigationReport>();
        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync().ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT report_json FROM investigations
            WHERE target_identifier = @ti
            ORDER BY timestamp DESC
            LIMIT 50;
        ";
        cmd.Parameters.AddWithValue("@ti", targetIdentifier);

        await using var reader = await cmd.ExecuteReaderAsync().ConfigureAwait(false);
        while (await reader.ReadAsync().ConfigureAwait(false))
        {
            string json = reader.GetString(0);
            try
            {
                var rep = JsonSerializer.Deserialize<InvestigationReport>(json);
                if (rep != null) list.Add(rep);
            }
            catch { }
        }

        return list;
    }

    public async Task DeleteInvestigationAsync(string id)
    {
        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync().ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM investigations WHERE id = @id;";
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
    }

    public async Task ClearAllAsync()
    {
        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync().ConfigureAwait(false);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM investigations;";
        await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
    }

    public void Dispose()
    {
    }
}
