namespace NetSentinel.Core;

/// <summary>
/// Source of Windows Firewall block events, either via native real-time WFP subscription
/// or via Security event log fallback (wevtutil).
/// </summary>
public interface IBlockEventSource : IDisposable
{
    /// <summary>Fired when a new blocked connection is detected.</summary>
    event Action<BlockEvent>? BlockDetected;

    /// <summary>Reads recent block events within the specified time window.</summary>
    IReadOnlyList<BlockEvent> ReadRecent(TimeSpan window, int max, bool includePacketDrops = false);

    /// <summary>Reads block events recorded after the specified record ID.</summary>
    IReadOnlyList<BlockEvent> ReadAfter(long lastRecordId, int max, bool includePacketDrops = false);

    /// <summary>True if the native WFP net-event subscription is active and delivering events.</summary>
    bool IsNativeSubscribed { get; }
}
