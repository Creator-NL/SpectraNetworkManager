using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace SpectraNetworkManager.Core.Ai;

public sealed class OllamaClient
{
    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(25)
    };

    public string EndpointUrl { get; set; } = "http://127.0.0.1:11434";
    public string DefaultModel { get; set; } = "qwen2.5:7b";

    public OllamaClient(string? endpointUrl = null, string? defaultModel = null)
    {
        if (!string.IsNullOrWhiteSpace(endpointUrl))
            EndpointUrl = endpointUrl.TrimEnd('/');
        if (!string.IsNullOrWhiteSpace(defaultModel))
            DefaultModel = defaultModel;
    }

    public async Task<bool> IsAvailableAsync(CancellationToken ct = default)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMilliseconds(1500));

            using var req = new HttpRequestMessage(HttpMethod.Get, $"{EndpointUrl}/api/tags");
            using var resp = await Http.SendAsync(req, cts.Token).ConfigureAwait(false);
            return resp.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public async Task<IReadOnlyList<string>> GetAvailableModelsAsync(CancellationToken ct = default)
    {
        var models = new List<string>();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(3));

            using var resp = await Http.GetAsync($"{EndpointUrl}/api/tags", cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return models;

            string json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("models", out var modelsProp) && modelsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var m in modelsProp.EnumerateArray())
                {
                    if (m.TryGetProperty("name", out var nameProp))
                    {
                        string? name = nameProp.GetString();
                        if (!string.IsNullOrWhiteSpace(name))
                            models.Add(name);
                    }
                }
            }
        }
        catch
        {
            // Silently return empty list if Ollama is offline
        }

        return models;
    }

    public async Task<string?> GenerateChatCompletionAsync(
        string systemPrompt,
        string userPrompt,
        string? modelOverride = null,
        CancellationToken ct = default)
    {
        string model = !string.IsNullOrWhiteSpace(modelOverride) ? modelOverride : DefaultModel;

        var payload = new
        {
            model = model,
            stream = false,
            format = "json",
            messages = new[]
            {
                new { role = "system", content = systemPrompt },
                new { role = "user", content = userPrompt }
            }
        };

        string requestJson = JsonSerializer.Serialize(payload);
        using var content = new StringContent(requestJson, Encoding.UTF8, "application/json");

        try
        {
            using var resp = await Http.PostAsync($"{EndpointUrl}/api/chat", content, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return null;

            string responseJson = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(responseJson);
            if (doc.RootElement.TryGetProperty("message", out var msgProp) &&
                msgProp.TryGetProperty("content", out var contentProp))
            {
                return contentProp.GetString();
            }
        }
        catch
        {
            // Timeout or connection error
            return null;
        }

        return null;
    }

    public async Task<string?> AskQuestionAsync(
        string systemPrompt,
        IEnumerable<(string Role, string Content)> conversationHistory,
        string? modelOverride = null,
        CancellationToken ct = default)
    {
        string model = !string.IsNullOrWhiteSpace(modelOverride) ? modelOverride : DefaultModel;

        var messagesList = new List<object>
        {
            new { role = "system", content = systemPrompt }
        };

        foreach (var (role, text) in conversationHistory)
        {
            messagesList.Add(new { role = role, content = text });
        }

        var payload = new
        {
            model = model,
            stream = false,
            messages = messagesList
        };

        string requestJson = JsonSerializer.Serialize(payload);
        using var content = new StringContent(requestJson, Encoding.UTF8, "application/json");

        try
        {
            using var resp = await Http.PostAsync($"{EndpointUrl}/api/chat", content, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return null;

            string responseJson = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(responseJson);
            if (doc.RootElement.TryGetProperty("message", out var msgProp) &&
                msgProp.TryGetProperty("content", out var contentProp))
            {
                return contentProp.GetString();
            }
        }
        catch
        {
            return null;
        }

        return null;
    }
}
