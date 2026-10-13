using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSentinel.Core.Ipc;

/// <summary>
/// Envelope for all messages transmitted across the NetSentinel IPC channel.
/// </summary>
public sealed class IpcMessage
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>
    /// Message type: "Request", "Response", or "Event".
    /// </summary>
    [JsonPropertyName("type")]
    public string Type { get; set; } = "Request";

    /// <summary>
    /// Action or event name, e.g. "Ping", "GetSnapshot", "BlockProgram", "MonitorTick".
    /// </summary>
    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// JSON payload content.
    /// </summary>
    [JsonPropertyName("payload")]
    public string? PayloadJson { get; set; }

    /// <summary>
    /// Indicates whether a Request was processed successfully.
    /// </summary>
    [JsonPropertyName("success")]
    public bool Success { get; set; } = true;

    /// <summary>
    /// Error description when Success is false.
    /// </summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }

    public static IpcMessage CreateRequest(string action, object? payload = null)
    {
        return new IpcMessage
        {
            Type = "Request",
            Action = action,
            PayloadJson = payload != null ? JsonSerializer.Serialize(payload) : null
        };
    }

    public static IpcMessage CreateResponse(IpcMessage request, object? payload = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new IpcMessage
        {
            Id = request.Id,
            Type = "Response",
            Action = request.Action,
            Success = true,
            PayloadJson = payload != null ? JsonSerializer.Serialize(payload) : null
        };
    }

    public static IpcMessage CreateErrorResponse(IpcMessage request, string error)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new IpcMessage
        {
            Id = request.Id,
            Type = "Response",
            Action = request.Action,
            Success = false,
            Error = error
        };
    }

    public static IpcMessage CreateEvent(string eventName, object? payload = null)
    {
        return new IpcMessage
        {
            Type = "Event",
            Action = eventName,
            PayloadJson = payload != null ? JsonSerializer.Serialize(payload) : null
        };
    }

    public T? DeserializePayload<T>(JsonSerializerOptions? options = null)
    {
        if (string.IsNullOrEmpty(PayloadJson))
            return default;
        return JsonSerializer.Deserialize<T>(PayloadJson, options);
    }
}
