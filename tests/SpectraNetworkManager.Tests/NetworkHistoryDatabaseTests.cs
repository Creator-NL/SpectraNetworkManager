using SpectraNetworkManager.Core;
using Xunit;

namespace SpectraNetworkManager.Tests;

public class NetworkHistoryDatabaseTests : IDisposable
{
    private readonly string _tempDbFile;

    public NetworkHistoryDatabaseTests()
    {
        _tempDbFile = Path.Combine(Path.GetTempPath(), $"spectranetworkmanager-test-netdb-{Guid.NewGuid():N}.db");
    }

    public void Dispose()
    {
        try
        {
            if (File.Exists(_tempDbFile)) File.Delete(_tempDbFile);
        }
        catch { }
    }

    [Fact]
    public async Task NetworkHistory_RecordsConnections_AndUpdatesLastSeen()
    {
        await using var db = new NetworkHistoryDatabase(_tempDbFile);

        var t1 = DateTimeOffset.UtcNow.AddMinutes(-5);
        var t2 = DateTimeOffset.UtcNow;

        db.RecordConnection(@"C:\App\test.exe", "93.184.216.34", 443, "TCP", t1);
        db.RecordConnection(@"C:\App\test.exe", "93.184.216.34", 443, "TCP", t2);

        // Allow batch flush
        await db.DisposeAsync();

        await using var dbReader = new NetworkHistoryDatabase(_tempDbFile);
        var recent = await dbReader.GetRecentConnectionsAsync(10);

        Assert.Single(recent);
        Assert.Equal(@"C:\App\test.exe", recent[0].Program);
        Assert.Equal("93.184.216.34", recent[0].Remote);
        Assert.Equal(443, recent[0].Port);
        Assert.Equal("TCP", recent[0].Proto);
        Assert.Equal(t2.ToUnixTimeSeconds(), recent[0].LastSeen.ToUnixTimeSeconds());
    }

    [Fact]
    public async Task NetworkHistory_AggregatesBandwidth_AndReturnsTopTalkers()
    {
        await using var db = new NetworkHistoryDatabase(_tempDbFile);

        var min = DateTimeOffset.UtcNow;
        db.RecordBandwidth(min, @"C:\App\heavy.exe", 1000, 500);
        db.RecordBandwidth(min, @"C:\App\heavy.exe", 2000, 1500);
        db.RecordBandwidth(min, @"C:\App\light.exe", 100, 50);

        await db.DisposeAsync();

        await using var dbReader = new NetworkHistoryDatabase(_tempDbFile);
        var top = await dbReader.GetTopTalkersAsync(TimeSpan.FromHours(1));

        Assert.Equal(2, top.Count);
        Assert.Equal(@"C:\App\heavy.exe", top[0].Program);
        Assert.Equal(3000, top[0].TotalBytesIn);
        Assert.Equal(2000, top[0].TotalBytesOut);

        Assert.Equal(@"C:\App\light.exe", top[1].Program);
        Assert.Equal(100, top[1].TotalBytesIn);
        Assert.Equal(50, top[1].TotalBytesOut);
    }

    [Fact]
    public async Task NetworkHistory_Pruning_RemovesOlderEntries()
    {
        await using var db = new NetworkHistoryDatabase(_tempDbFile);

        var oldTime = DateTimeOffset.UtcNow.AddDays(-35);
        var newTime = DateTimeOffset.UtcNow;

        db.RecordConnection(@"C:\App\old.exe", "1.1.1.1", 53, "UDP", oldTime);
        db.RecordConnection(@"C:\App\new.exe", "8.8.8.8", 53, "UDP", newTime);

        await db.DisposeAsync();

        await using var dbReader = new NetworkHistoryDatabase(_tempDbFile);
        await dbReader.PruneOlderThanDaysAsync(30);

        var remaining = await dbReader.GetRecentConnectionsAsync(10);
        Assert.Single(remaining);
        Assert.Equal(@"C:\App\new.exe", remaining[0].Program);
    }
}
