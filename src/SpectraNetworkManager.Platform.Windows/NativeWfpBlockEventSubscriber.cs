using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using SpectraNetworkManager.Core;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace SpectraNetworkManager.Platform.Windows;

/// <summary>
/// Subscribes to real-time Windows Filtering Platform (WFP) network drop events natively,
/// without requiring the Security audit policy (auditpol) to be enabled.
/// If native subscription cannot be acquired (e.g. non-elevated), seamlessly falls back
/// to reading the Security event log via FirewallBlockLog.
/// </summary>
[SupportedOSPlatform("windows6.1")]
public sealed class NativeWfpBlockEventSubscriber : IBlockEventSource
{
    private const int MaxBufferSize = 1000;
    private const uint RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF;

    private readonly DevicePathConverter _pathConverter = new();
    private readonly FirewallBlockLog _fallback = new();
    private readonly object _lock = new();
    private readonly LinkedList<BlockEvent> _events = new();

    private FwpmEngineClose0SafeHandle? _engineHandle;
    private SafeFileHandle? _eventsHandle;
    private FWPM_NET_EVENT_CALLBACK0? _callbackDelegate;
    private long _recordCounter;
    private bool _isNativeSubscribed;
    private bool _disposed;

    public event Action<BlockEvent>? BlockDetected;

    public bool IsNativeSubscribed => _isNativeSubscribed;

    public NativeWfpBlockEventSubscriber()
    {
        _fallback.BlockDetected += ev => BlockDetected?.Invoke(ev);
        TrySubscribeNative();
    }

    private unsafe void TrySubscribeNative()
    {
        try
        {
            uint openStatus = PInvoke.FwpmEngineOpen0(
                authnService: RPC_C_AUTHN_DEFAULT,
                authIdentity: null,
                session: null,
                out var engineHandle);

            if (openStatus != 0 || engineHandle.IsInvalid)
            {
                _isNativeSubscribed = false;
                return;
            }

            _engineHandle = engineHandle;
            _callbackDelegate = OnNetEvent;

            var subscription = new FWPM_NET_EVENT_SUBSCRIPTION0
            {
                enumTemplate = null,
                flags = 0,
                sessionKey = default
            };

            uint subStatus = PInvoke.FwpmNetEventSubscribe0(
                _engineHandle,
                in subscription,
                _callbackDelegate,
                null,
                out var eventsHandle);

            if (subStatus != 0 || eventsHandle.IsInvalid)
            {
                _engineHandle.Dispose();
                _engineHandle = null;
                _isNativeSubscribed = false;
                return;
            }

            _eventsHandle = eventsHandle;
            _isNativeSubscribed = true;
        }
        catch
        {
            _isNativeSubscribed = false;
            _engineHandle?.Dispose();
            _engineHandle = null;
            _eventsHandle?.Dispose();
            _eventsHandle = null;
        }
    }

    private unsafe void OnNetEvent(void* context, FWPM_NET_EVENT1* netEvent)
    {
        try
        {
            if (netEvent == null) return;
            if (netEvent->type != FWPM_NET_EVENT_TYPE.FWPM_NET_EVENT_TYPE_CLASSIFY_DROP) return;

            var header = netEvent->header;
            var drop = netEvent->classifyDrop;
            if (drop == null) return;

            long fileTime = ((long)header.timeStamp.dwHighDateTime << 32) | (uint)header.timeStamp.dwLowDateTime;
            var time = fileTime > 0 ? DateTimeOffset.FromFileTime(fileTime) : DateTimeOffset.UtcNow;

            string appPath = "";
            if (header.appId.data != null && header.appId.size > 0)
            {
                string raw = new string((char*)header.appId.data, 0, (int)(header.appId.size / 2)).TrimEnd('\0');
                appPath = _pathConverter.ToDosPath(raw);
            }

            bool inbound = drop->msFwpDirection == 0x00003900; // FWP_DIRECTION_IN

            string srcAddr = "";
            string dstAddr = "";
            int srcPort = header.localPort;
            int dstPort = header.remotePort;

            if (header.ipVersion == FWP_IP_VERSION.FWP_IP_VERSION_V4)
            {
                Span<byte> localBytes = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(localBytes, header.localAddrV4);
                Span<byte> remoteBytes = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(remoteBytes, header.remoteAddrV4);

                string localIp = new IPAddress(localBytes).ToString();
                string remoteIp = new IPAddress(remoteBytes).ToString();

                srcAddr = inbound ? remoteIp : localIp;
                dstAddr = inbound ? localIp : remoteIp;
                srcPort = inbound ? header.remotePort : header.localPort;
                dstPort = inbound ? header.localPort : header.remotePort;
            }
            else if (header.ipVersion == FWP_IP_VERSION.FWP_IP_VERSION_V6)
            {
                string localIp = new IPAddress(header.localAddrV6.byteArray16.AsReadOnlySpan()).ToString();
                string remoteIp = new IPAddress(header.remoteAddrV6.byteArray16.AsReadOnlySpan()).ToString();

                srcAddr = inbound ? remoteIp : localIp;
                dstAddr = inbound ? localIp : remoteIp;
                srcPort = inbound ? header.remotePort : header.localPort;
                dstPort = inbound ? header.localPort : header.remotePort;
            }

            long id = Interlocked.Increment(ref _recordCounter);
            var block = new BlockEvent(
                RecordId: id,
                Time: time,
                ProcessId: 0,
                Application: appPath,
                Inbound: inbound,
                SourceAddress: srcAddr,
                SourcePort: srcPort,
                DestinationAddress: dstAddr,
                DestinationPort: dstPort,
                ProtocolNumber: header.ipProtocol,
                IsPacketDrop: false
            );

            AddEvent(block);
            BlockDetected?.Invoke(block);
        }
        catch
        {
            // Must never let an unhandled exception leak into the native WFP callback thread
        }
    }

    private void AddEvent(BlockEvent ev)
    {
        lock (_lock)
        {
            _events.AddLast(ev);
            while (_events.Count > MaxBufferSize)
            {
                _events.RemoveFirst();
            }
        }
    }

    public IReadOnlyList<BlockEvent> ReadRecent(TimeSpan window, int max, bool includePacketDrops = false)
    {
        if (!_isNativeSubscribed)
        {
            return _fallback.ReadRecent(window, max, includePacketDrops);
        }

        var cutoff = DateTimeOffset.UtcNow - window;
        lock (_lock)
        {
            return _events
                .Where(e => e.Time >= cutoff && (includePacketDrops || !e.IsPacketDrop))
                .Reverse()
                .Take(max)
                .ToList();
        }
    }

    public IReadOnlyList<BlockEvent> ReadAfter(long lastRecordId, int max, bool includePacketDrops = false)
    {
        if (!_isNativeSubscribed)
        {
            return _fallback.ReadAfter(lastRecordId, max, includePacketDrops);
        }

        lock (_lock)
        {
            return _events
                .Where(e => e.RecordId > lastRecordId && (includePacketDrops || !e.IsPacketDrop))
                .Take(max)
                .ToList();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            if (_eventsHandle is { IsInvalid: false })
            {
                _eventsHandle.Dispose();
            }
            if (_engineHandle is { IsInvalid: false })
            {
                _engineHandle.Dispose();
            }
        }
        catch { }

        _fallback.Dispose();
    }
}
