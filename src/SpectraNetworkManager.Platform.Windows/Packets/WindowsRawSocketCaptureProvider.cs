using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

[SupportedOSPlatform("windows")]
public sealed class WindowsRawSocketCaptureProvider : IPacketCaptureProvider
{
    // SIO_RCVALL IOControl Code for Windows Winsock raw sockets
    private const int SioRcvAll = unchecked((int)0x98000001);

    private Socket? _socket;
    private CancellationTokenSource? _cts;
    private Task? _workerTask;
    private long _packetSequence;
    private readonly Action<CapturedPacket>? _enricher;

    public event Action<CapturedPacket>? PacketCaptured;
    public event Action<string>? StatusChanged;

    public string ProviderName => "Windows Raw Sockets (SIO_RCVALL)";
    public bool IsRunning => _socket != null && _workerTask != null && !_workerTask.IsCompleted;

    public WindowsRawSocketCaptureProvider(Action<CapturedPacket>? processEnricher = null)
    {
        _enricher = processEnricher;
    }

    public Task<bool> StartAsync(string? interfaceIp = null, CancellationToken ct = default)
    {
        if (IsRunning) return Task.FromResult(true);

        IPAddress? bindAddress = null;
        if (!string.IsNullOrWhiteSpace(interfaceIp) && IPAddress.TryParse(interfaceIp.Trim(), out var parsed))
        {
            bindAddress = parsed;
        }
        else
        {
            bindAddress = GetBestActiveIPv4Address();
        }

        if (bindAddress == null || bindAddress.Equals(IPAddress.Any) || bindAddress.Equals(IPAddress.None))
        {
            StatusChanged?.Invoke("No active local IPv4 interface found for packet capture.");
            return Task.FromResult(false);
        }

        try
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            _socket.Bind(new IPEndPoint(bindAddress, 0));

            // SIO_RCVALL: 1 = RCVALL_ON (captures all incoming and outgoing packets on the interface)
            byte[] inValue = BitConverter.GetBytes(1);
            byte[] outValue = new byte[4];
            _socket.IOControl(unchecked((IOControlCode)SioRcvAll), inValue, outValue);

            _cts = new CancellationTokenSource();
            _workerTask = Task.Factory.StartNew(
                () => CaptureLoop(bindAddress, _cts.Token),
                TaskCreationOptions.LongRunning);

            StatusChanged?.Invoke($"Capturing live packets on {bindAddress} (SIO_RCVALL)");
            return Task.FromResult(true);
        }
        catch (SocketException ex)
        {
            RotatingFileLogger.LogWarn($"WindowsRawSocketCaptureProvider failed to start: {ex.Message} (Error code {ex.NativeErrorCode})");
            StatusChanged?.Invoke($"Capture failed: {ex.Message}. (Note: Raw socket capture requires Administrator rights)");
            CleanupSocket();
            return Task.FromResult(false);
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogError($"WindowsRawSocketCaptureProvider unexpected error", ex);
            StatusChanged?.Invoke($"Capture initialization failed: {ex.Message}");
            CleanupSocket();
            return Task.FromResult(false);
        }
    }

    private void CaptureLoop(IPAddress localIp, CancellationToken ct)
    {
        byte[] buffer = new byte[65536];

        while (!ct.IsCancellationRequested && _socket != null)
        {
            try
            {
                int bytesRead = _socket.Receive(buffer);
                if (bytesRead <= 0) continue;

                var now = DateTimeOffset.UtcNow;
                long id = Interlocked.Increment(ref _packetSequence);

                // Determine direction based on local interface IP
                bool isInbound = false;
                if (bytesRead >= 20)
                {
                    var dstSpan = buffer.AsSpan(16, 4);
                    var dstIp = new IPAddress(dstSpan);
                    if (dstIp.Equals(localIp) || dstIp.Equals(IPAddress.Broadcast))
                    {
                        isInbound = true;
                    }
                }

                var packet = ProtocolDissectors.Dissect(buffer.AsSpan(0, bytesRead), id, now, isInbound);

                // Correlate with active socket tables for process attribution
                try
                {
                    _enricher?.Invoke(packet);
                }
                catch { }

                PacketCaptured?.Invoke(packet);
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.Interrupted or SocketError.OperationAborted or SocketError.Shutdown)
            {
                break;
            }
            catch (Exception)
            {
                if (ct.IsCancellationRequested) break;
            }
        }
    }

    public Task StopAsync()
    {
        CleanupSocket();
        StatusChanged?.Invoke("Packet capture stopped.");
        return Task.CompletedTask;
    }

    private void CleanupSocket()
    {
        try { _cts?.Cancel(); } catch { }
        try { _socket?.Close(); } catch { }
        try { _socket?.Dispose(); } catch { }
        _socket = null;
        _cts?.Dispose();
        _cts = null;
    }

    public static IPAddress? GetBestActiveIPv4Address()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                var ipProps = ni.GetIPProperties();
                foreach (var unicast in ipProps.UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(unicast.Address) &&
                        !unicast.Address.ToString().StartsWith("169.254.", StringComparison.Ordinal))
                    {
                        return unicast.Address;
                    }
                }
            }
        }
        catch { }
        return null;
    }

    public static List<IPAddress> GetAllActiveIPv4Addresses()
    {
        var list = new List<IPAddress>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                var ipProps = ni.GetIPProperties();
                foreach (var unicast in ipProps.UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(unicast.Address))
                    {
                        list.Add(unicast.Address);
                    }
                }
            }
        }
        catch { }
        return list;
    }

    public void Dispose()
    {
        StopAsync();
    }
}
