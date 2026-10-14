using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Tests;

public sealed class DnsHistoryDatabaseTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _dbPath;

    public DnsHistoryDatabaseTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "SpectraNetworkManagerTests_History_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "history.db");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public async Task DnsHistoryDatabase_EnqueuesAndRetrievesEntries()
    {
        using var db = new DnsHistoryDatabase(_dbPath);

        var entry1 = new DnsLogEntry(DateTimeOffset.Now.AddSeconds(-2), "127.0.0.1", "example.com", "A", DnsOutcome.Forwarded, null, 15);
        var entry2 = new DnsLogEntry(DateTimeOffset.Now.AddSeconds(-1), "192.168.1.5", "doubleclick.net", "A", DnsOutcome.Blocked, "StevenBlack list", 1);

        db.Enqueue(entry1);
        db.Enqueue(entry2);
        db.Flush();

        var recent = await db.GetRecentEntriesAsync(limit: 10);

        Assert.Equal(2, recent.Count);
        // Ordered by id DESC (newest first)
        Assert.Equal("doubleclick.net", recent[0].Domain);
        Assert.Equal(DnsOutcome.Blocked, recent[0].Outcome);
        Assert.Equal("StevenBlack list", recent[0].Detail);

        Assert.Equal("example.com", recent[1].Domain);
        Assert.Equal(DnsOutcome.Forwarded, recent[1].Outcome);
    }

    [Fact]
    public async Task DnsHistoryDatabase_AppliesPrivacySettings()
    {
        using var db = new DnsHistoryDatabase(_dbPath);

        var entry1 = new DnsLogEntry(DateTimeOffset.Now, "192.168.1.155", "secret-site.org", "A", DnsOutcome.Forwarded, null, 10);
        var entry2 = new DnsLogEntry(DateTimeOffset.Now, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "private-data.com", "AAAA", DnsOutcome.Forwarded, null, 8);

        db.Enqueue(entry1, anonymizeIps: true, redactDomains: true);
        db.Enqueue(entry2, anonymizeIps: true, redactDomains: true);
        db.Flush();

        var recent = await db.GetRecentEntriesAsync(limit: 10);

        Assert.Equal(2, recent.Count);
        Assert.Equal("[redacted]", recent[0].Domain);
        Assert.Equal("[redacted]", recent[1].Domain);

        // IPv4 last octet masked
        Assert.Equal("192.168.1.0", recent[1].Client);
        // IPv6 host bits masked
        Assert.StartsWith("2001:db8:85a3::", recent[0].Client);
    }

    [Fact]
    public async Task DnsHistoryDatabase_ExportsCsvCorrectly()
    {
        using var db = new DnsHistoryDatabase(_dbPath);

        var entry = new DnsLogEntry(DateTimeOffset.Parse("2026-10-13T12:00:00Z"), "10.0.0.1", "test,domain.com", "A", DnsOutcome.Forwarded, "note with \"quotes\"", 25);
        db.Enqueue(entry);
        db.Flush();

        using var sw = new StringWriter();
        await db.ExportCsvAsync(sw);
        string csv = sw.ToString();

        Assert.Contains("Timestamp,Client,Domain,Type,Outcome,Detail,DurationMs", csv);
        Assert.Contains("\"test,domain.com\"", csv);
        Assert.Contains("\"note with \"\"quotes\"\"\"", csv);
    }
}
