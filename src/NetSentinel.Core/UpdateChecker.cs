using System.Net.Http;
using System.Text.Json;

namespace NetSentinel.Core;

public sealed record UpdateCheckResult(
    bool IsSuccess,
    bool IsUpdateAvailable,
    string? CurrentVersion,
    string? LatestVersion,
    string? ReleaseName,
    string? ReleaseNotes,
    string? HtmlUrl,
    string? ErrorMessage);

public sealed class UpdateChecker
{
    public const string DefaultApiUrl = "https://api.github.com/repos/Creator-NL/NetSentinel/releases/latest";

    private readonly HttpClient _httpClient;
    private readonly string _apiUrl;

    public UpdateChecker(HttpClient? httpClient = null, string? apiUrl = null)
    {
        _httpClient = httpClient ?? new HttpClient();
        _apiUrl = apiUrl ?? DefaultApiUrl;
    }

    public async Task<UpdateCheckResult> CheckForUpdatesAsync(string currentVersion, CancellationToken ct = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, _apiUrl);
            request.Headers.UserAgent.ParseAdd($"NetSentinel-UpdateChecker/{currentVersion}");
            request.Headers.Accept.ParseAdd("application/vnd.github.v3+json");

            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return new UpdateCheckResult(
                    IsSuccess: false,
                    IsUpdateAvailable: false,
                    CurrentVersion: currentVersion,
                    LatestVersion: null,
                    ReleaseName: null,
                    ReleaseNotes: null,
                    HtmlUrl: null,
                    ErrorMessage: $"GitHub API returned status {(int)response.StatusCode} {response.ReasonPhrase}");
            }

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string? tagName = root.TryGetProperty("tag_name", out var tagElem) ? tagElem.GetString() : null;
            string? name = root.TryGetProperty("name", out var nameElem) ? nameElem.GetString() : null;
            string? body = root.TryGetProperty("body", out var bodyElem) ? bodyElem.GetString() : null;
            string? htmlUrl = root.TryGetProperty("html_url", out var urlElem) ? urlElem.GetString() : null;

            if (string.IsNullOrWhiteSpace(tagName))
            {
                return new UpdateCheckResult(
                    IsSuccess: false,
                    IsUpdateAvailable: false,
                    CurrentVersion: currentVersion,
                    LatestVersion: null,
                    ReleaseName: null,
                    ReleaseNotes: null,
                    HtmlUrl: null,
                    ErrorMessage: "GitHub release payload did not contain a valid tag_name.");
            }

            string cleanLatest = tagName.TrimStart('v', 'V');
            string cleanCurrent = currentVersion.TrimStart('v', 'V');

            bool updateAvailable = IsNewerVersion(cleanLatest, cleanCurrent);

            return new UpdateCheckResult(
                IsSuccess: true,
                IsUpdateAvailable: updateAvailable,
                CurrentVersion: currentVersion,
                LatestVersion: tagName,
                ReleaseName: name,
                ReleaseNotes: body,
                HtmlUrl: htmlUrl,
                ErrorMessage: null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new UpdateCheckResult(
                IsSuccess: false,
                IsUpdateAvailable: false,
                CurrentVersion: currentVersion,
                LatestVersion: null,
                ReleaseName: null,
                ReleaseNotes: null,
                HtmlUrl: null,
                ErrorMessage: ex.Message);
        }
    }

    public static bool IsNewerVersion(string latestStr, string currentStr)
    {
        if (Version.TryParse(latestStr, out var latest) && Version.TryParse(currentStr, out var current))
        {
            return latest > current;
        }

        // Fallback: compare numerical dot-separated version components
        var latestParts = latestStr.Split('.');
        var currentParts = currentStr.Split('.');
        int length = Math.Max(latestParts.Length, currentParts.Length);

        for (int i = 0; i < length; i++)
        {
            int lVal = i < latestParts.Length && int.TryParse(latestParts[i], out int l) ? l : 0;
            int cVal = i < currentParts.Length && int.TryParse(currentParts[i], out int c) ? c : 0;
            if (lVal > cVal) return true;
            if (lVal < cVal) return false;
        }

        return false;
    }
}
