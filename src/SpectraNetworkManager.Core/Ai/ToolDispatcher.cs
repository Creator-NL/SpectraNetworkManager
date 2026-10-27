using System.Text.Json;

namespace SpectraNetworkManager.Core.Ai;

public interface IInvestigationToolContext
{
    Task<string> GetProcessInfoAsync(int pid, CancellationToken ct);
    Task<string> VerifyExecutableAsync(string path, CancellationToken ct);
    Task<string> GetProcessConnectionsAsync(string programOrPid, CancellationToken ct);
    Task<string> GetDnsHistoryAsync(string query, CancellationToken ct);
    Task<string> GetLocalListeningPortsAsync(CancellationToken ct);
    Task<string> GetStartupEntriesAsync(string filter, CancellationToken ct);
    Task<string> GetCaptureSummaryAsync(CancellationToken ct);
}

public sealed class ToolDispatcher
{
    private readonly IInvestigationToolContext _context;
    private int _turnCount;
    private const int MaxTurns = 3;

    public ToolDispatcher(IInvestigationToolContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public int RemainingTurns => Math.Max(0, MaxTurns - _turnCount);

    public async Task<string> ExecuteToolAsync(string toolName, string argumentsJson, CancellationToken ct = default)
    {
        if (_turnCount >= MaxTurns)
        {
            return JsonSerializer.Serialize(new
            {
                error = "Tool call quota exceeded. Maximum of 3 tool calls allowed per investigation session."
            });
        }

        _turnCount++;

        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(argumentsJson) ? "{}" : argumentsJson);
            var root = doc.RootElement;

            return toolName.ToLowerInvariant() switch
            {
                "get_process_info" => await HandleGetProcessInfoAsync(root, ct).ConfigureAwait(false),
                "verify_executable" => await HandleVerifyExecutableAsync(root, ct).ConfigureAwait(false),
                "get_process_connections" => await HandleGetProcessConnectionsAsync(root, ct).ConfigureAwait(false),
                "get_dns_history" => await HandleGetDnsHistoryAsync(root, ct).ConfigureAwait(false),
                "get_local_listening_ports" => await _context.GetLocalListeningPortsAsync(ct).ConfigureAwait(false),
                "get_startup_entries" => await HandleGetStartupEntriesAsync(root, ct).ConfigureAwait(false),
                "get_capture_summary" => await _context.GetCaptureSummaryAsync(ct).ConfigureAwait(false),
                _ => JsonSerializer.Serialize(new { error = $"Unknown or unauthorized tool: '{toolName}'" })
            };
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = $"Tool execution error: {ex.Message}" });
        }
    }

    private async Task<string> HandleGetProcessInfoAsync(JsonElement root, CancellationToken ct)
    {
        int pid = 0;
        if (root.TryGetProperty("pid", out var pidProp))
            pidProp.TryGetInt32(out pid);

        if (pid <= 0)
            return JsonSerializer.Serialize(new { error = "Invalid or missing 'pid' parameter." });

        return await _context.GetProcessInfoAsync(pid, ct).ConfigureAwait(false);
    }

    private async Task<string> HandleVerifyExecutableAsync(JsonElement root, CancellationToken ct)
    {
        string? path = root.TryGetProperty("path", out var pathProp) ? pathProp.GetString() : null;
        if (string.IsNullOrWhiteSpace(path))
            return JsonSerializer.Serialize(new { error = "Missing 'path' parameter." });

        return await _context.VerifyExecutableAsync(PromptSanitizer.Sanitize(path, 260), ct).ConfigureAwait(false);
    }

    private async Task<string> HandleGetProcessConnectionsAsync(JsonElement root, CancellationToken ct)
    {
        string target = "";
        if (root.TryGetProperty("program", out var progProp))
            target = progProp.GetString() ?? "";
        else if (root.TryGetProperty("pid", out var pidProp))
            target = pidProp.ToString();

        return await _context.GetProcessConnectionsAsync(PromptSanitizer.Sanitize(target, 128), ct).ConfigureAwait(false);
    }

    private async Task<string> HandleGetDnsHistoryAsync(JsonElement root, CancellationToken ct)
    {
        string query = root.TryGetProperty("domain", out var dProp) ? dProp.GetString() ?? "" : "";
        return await _context.GetDnsHistoryAsync(PromptSanitizer.Sanitize(query, 128), ct).ConfigureAwait(false);
    }

    private async Task<string> HandleGetStartupEntriesAsync(JsonElement root, CancellationToken ct)
    {
        string filter = root.TryGetProperty("filter", out var fProp) ? fProp.GetString() ?? "" : "";
        return await _context.GetStartupEntriesAsync(PromptSanitizer.Sanitize(filter, 128), ct).ConfigureAwait(false);
    }
}
