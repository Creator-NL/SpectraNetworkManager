using System.Net;
using System.Text;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Tests;

public sealed class UpdateCheckerTests
{
    private sealed class MockHttpHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public HttpResponseMessage ResponseToReturn { get; set; } = new(HttpStatusCode.OK);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(ResponseToReturn);
        }
    }

    [Theory]
    [InlineData("1.1.0", "1.0.0", true)]
    [InlineData("2.0.0", "1.9.9", true)]
    [InlineData("1.0.1", "1.0.0", true)]
    [InlineData("1.0.0", "1.0.0", false)]
    [InlineData("0.9.9", "1.0.0", false)]
    [InlineData("1.0.0", "1.0.1", false)]
    [InlineData("1.0.0.5", "1.0.0.4", true)]
    public void IsNewerVersion_EvaluatesCorrectly(string latest, string current, bool expected)
    {
        bool result = UpdateChecker.IsNewerVersion(latest, current);
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task CheckForUpdates_DetectsNewerRelease()
    {
        var mock = new MockHttpHandler();
        string json = """
        {
            "tag_name": "v1.2.0",
            "name": "SpectraNetworkManager 1.2.0",
            "body": "Bug fixes and improvements",
            "html_url": "https://github.com/Creator-NL/SpectraNetworkManager/releases/tag/v1.2.0"
        }
        """;

        mock.ResponseToReturn = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        using var client = new HttpClient(mock);
        var checker = new UpdateChecker(client);

        var result = await checker.CheckForUpdatesAsync("1.0.0");

        Assert.True(result.IsSuccess);
        Assert.True(result.IsUpdateAvailable);
        Assert.Equal("1.0.0", result.CurrentVersion);
        Assert.Equal("v1.2.0", result.LatestVersion);
        Assert.Equal("SpectraNetworkManager 1.2.0", result.ReleaseName);
        Assert.Equal("Bug fixes and improvements", result.ReleaseNotes);
        Assert.Equal("https://github.com/Creator-NL/SpectraNetworkManager/releases/tag/v1.2.0", result.HtmlUrl);

        Assert.NotNull(mock.LastRequest);
        Assert.Contains("SpectraNetworkManager-UpdateChecker/1.0.0", mock.LastRequest.Headers.UserAgent.ToString());
    }

    [Fact]
    public async Task CheckForUpdates_HandlesUpToDateRelease()
    {
        var mock = new MockHttpHandler();
        string json = """
        {
            "tag_name": "v1.0.0",
            "name": "SpectraNetworkManager 1.0.0",
            "body": "Initial Release",
            "html_url": "https://github.com/Creator-NL/SpectraNetworkManager/releases/tag/v1.0.0"
        }
        """;

        mock.ResponseToReturn = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        using var client = new HttpClient(mock);
        var checker = new UpdateChecker(client);

        var result = await checker.CheckForUpdatesAsync("1.0.0");

        Assert.True(result.IsSuccess);
        Assert.False(result.IsUpdateAvailable);
    }

    [Fact]
    public async Task CheckForUpdates_HandlesHttpErrorGracefully()
    {
        var mock = new MockHttpHandler
        {
            ResponseToReturn = new HttpResponseMessage(HttpStatusCode.NotFound)
        };

        using var client = new HttpClient(mock);
        var checker = new UpdateChecker(client);

        var result = await checker.CheckForUpdatesAsync("1.0.0");

        Assert.False(result.IsSuccess);
        Assert.False(result.IsUpdateAvailable);
        Assert.NotNull(result.ErrorMessage);
    }

    [Fact]
    public void AppSettingsStore_SavesAndLoadsCorrectly()
    {
        string tempFile = Path.Combine(Path.GetTempPath(), $"spectranetworkmanager-test-settings-{Guid.NewGuid():N}.json");
        try
        {
            var store = new AppSettingsStore(tempFile);
            Assert.False(store.Settings.FirstRunCompleted);
            Assert.Equal("WatchOnly", store.Settings.InitialOperatingMode);

            var updated = store.Settings with
            {
                FirstRunCompleted = true,
                InitialOperatingMode = "AskMode",
                CheckForUpdatesOnStartup = true
            };
            store.Save(updated);

            var reloaded = new AppSettingsStore(tempFile);
            Assert.True(reloaded.Settings.FirstRunCompleted);
            Assert.Equal("AskMode", reloaded.Settings.InitialOperatingMode);
            Assert.True(reloaded.Settings.CheckForUpdatesOnStartup);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }
}
