using NetSentinel.Core;
using Xunit;

namespace NetSentinel.Tests;

public class SupportInfoAndLoggingTests : IDisposable
{
    private readonly string _tempLogFile;

    public SupportInfoAndLoggingTests()
    {
        _tempLogFile = Path.Combine(Path.GetTempPath(), $"netsentinel-log-{Guid.NewGuid():N}.log");
    }

    public void Dispose()
    {
        try
        {
            if (File.Exists(_tempLogFile)) File.Delete(_tempLogFile);
        }
        catch { }
    }

    [Fact]
    public void Display_BytesAndRate_FormatsExpectedUnits()
    {
        Assert.Equal("500 B", Display.Bytes(500));
        Assert.Equal("1.0 KB", Display.Bytes(1024));
        Assert.Equal("1.5 MB", Display.Bytes((long)(1.5 * 1024 * 1024)));
        Assert.Equal("2.0 GB", Display.Bytes(2L * 1024 * 1024 * 1024));

        Assert.Equal("\u2014", Display.Rate(0));
        Assert.Equal("1.0 KB/s", Display.Rate(1024));
        Assert.Equal("5.0 MB/s", Display.Rate(5 * 1024 * 1024));
    }

    [Fact]
    public void RotatingFileLogger_WritesAndRetrievesRecentEntries()
    {
        using var logger = new RotatingFileLogger(_tempLogFile);

        logger.Log(LogLevel.Info, "Test message one");
        logger.Log(LogLevel.Warn, "Test warning two");

        var entries = logger.GetRecentEntries(10);
        Assert.Equal(2, entries.Count);
        Assert.Equal(LogLevel.Info, entries[0].Level);
        Assert.Equal("Test message one", entries[0].Message);
        Assert.Equal(LogLevel.Warn, entries[1].Level);

        Assert.True(File.Exists(_tempLogFile));
        string content = File.ReadAllText(_tempLogFile);
        Assert.Contains("Test message one", content);
        Assert.Contains("Test warning two", content);
    }

    [Fact]
    public void SupportInfoGenerator_RedactsUserPathsAndGeneratesMarkdown()
    {
        string rawPath = @"C:\Users\JohnDoe\AppData\Local\NetSentinel\rules.json";
        string redacted = SupportInfoGenerator.RedactPaths(rawPath);
        Assert.Equal(@"C:\Users\<redacted>\AppData\Local\NetSentinel\rules.json", redacted);

        var logs = new List<LogEntry>
        {
            new(DateTimeOffset.UtcNow, LogLevel.Info, $@"Loaded config from {rawPath}", null)
        };

        string output = SupportInfoGenerator.Generate(
            engineStatusSummary: "Running with 1 client",
            ruleCount: 5,
            blocklistCount: 100000,
            recentLogs: logs,
            options: new SupportInfoOptions(RedactUserPaths: true, RedactDomains: false));

        Assert.Contains("# NetSentinel Support Diagnostic Info", output);
        Assert.Contains("Active Rule Count: 5", output);
        Assert.Contains("Blocklist Domains Loaded: 100,000", output);
        Assert.Contains(@"C:\Users\<redacted>\AppData", output);
        Assert.DoesNotContain("JohnDoe", output);
    }
}
