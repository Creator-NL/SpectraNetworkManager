using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SpectraNetworkManager.Platform.Windows.Mobile;

public sealed record DhcpLeaseInfo(
    string IpAddress,
    string MacAddress,
    string Hostname,
    DateTime AssignedUtc
);

/// <summary>
/// Built-in RFC 2131 DHCP Server (UDP Port 67) for SpectraNetworkManager.
/// When enabled on the LAN, automatically assigns IPv4 leases (.150 - .199) to phones and Smart TVs
/// with Default Gateway (Option 3) = Spectra PC, DNS Server (Option 6) = Spectra PC,
/// and WPAD Auto-Proxy (Option 252) = http://PC_IP:8888/wpad.dat.
/// </summary>
public sealed class SpectraDhcpServer : IDisposable
{
    private const int DhcpServerPort = 67;
    private const int DhcpClientPort = 68;
    private const byte BootRequest = 1;
    private const byte BootReply = 2;

    private readonly ConcurrentDictionary<string, DhcpLeaseInfo> _leasesByMac = new(StringComparer.OrdinalIgnoreCase);
    private UdpClient? _udp;
    private CancellationTokenSource? _cts;
    private IPAddress _serverIp = IPAddress.Parse("192.168.178.203");
    private IPAddress _subnetMask = IPAddress.Parse("255.255.255.0");
    private int _proxyPort = 8888;

    public bool IsRunning { get; private set; }
    public int ActiveLeaseCount => _leasesByMac.Count;
    public IReadOnlyCollection<DhcpLeaseInfo> Leases => _leasesByMac.Values.ToList();

    public event Action<DhcpLeaseInfo>? LeaseAssigned;

    public void Start(IPAddress? serverLanIp = null, int proxyPort = 8888)
    {
        if (IsRunning) return;

        _proxyPort = proxyPort;
        if (serverLanIp != null && serverLanIp.AddressFamily == AddressFamily.InterNetwork)
        {
            _serverIp = serverLanIp;
        }
        else if (TryDetectLanInterface(out var detectedIp, out var detectedMask))
        {
            _serverIp = detectedIp;
            _subnetMask = detectedMask;
        }

        try
        {
            _cts = new CancellationTokenSource();
            var udp = new UdpClient();
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, DhcpServerPort));

            _udp = udp;
            IsRunning = true;
            _ = Task.Run(() => ReceiveLoopAsync(udp, _cts.Token));
        }
        catch
        {
            Stop();
            throw;
        }
    }

    public void Stop()
    {
        IsRunning = false;
        try { _cts?.Cancel(); } catch { }
        try { _udp?.Dispose(); } catch { }
        _udp = null;
    }

    private async Task ReceiveLoopAsync(UdpClient udp, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var res = await udp.ReceiveAsync(ct).ConfigureAwait(false);
                var buf = res.Buffer;
                if (buf.Length < 240 || buf[0] != BootRequest) continue;

                // Verify DHCP Magic Cookie (99, 130, 83, 99) at offset 236
                if (buf[236] != 99 || buf[237] != 130 || buf[238] != 83 || buf[239] != 99)
                    continue;

                byte hlen = buf[2];
                if (hlen != 6) continue;

                byte[] xid = buf[4..8];
                byte[] chaddr = buf[28..34];
                string mac = string.Join("-", chaddr.Select(b => b.ToString("X2")));

                // Parse DHCP options starting at offset 240
                byte msgType = 0;
                IPAddress? requestedIp = null;
                string hostname = "";

                int idx = 240;
                while (idx < buf.Length)
                {
                    byte opt = buf[idx++];
                    if (opt == 255) break; // End Option
                    if (opt == 0) continue; // Pad
                    if (idx >= buf.Length) break;

                    int len = buf[idx++];
                    if (idx + len > buf.Length) break;

                    switch (opt)
                    {
                        case 53 when len >= 1: // DHCP Message Type
                            msgType = buf[idx];
                            break;
                        case 50 when len == 4: // Requested IP Address
                            requestedIp = new IPAddress(buf.AsSpan(idx, 4));
                            break;
                        case 12 when len > 0: // Hostname
                            hostname = Encoding.ASCII.GetString(buf, idx, len).Trim('\0', ' ');
                            break;
                    }

                    idx += len;
                }

                // 1 = DHCPDISCOVER, 3 = DHCPREQUEST
                if (msgType != 1 && msgType != 3) continue;

                IPAddress assignedIp = AllocateIpForMac(mac, chaddr, requestedIp);
                byte replyType = msgType == 1 ? (byte)2 : (byte)5; // 2 = DHCPOFFER, 5 = DHCPACK

                byte[] replyPacket = BuildDhcpReply(xid, chaddr, assignedIp, replyType);
                var broadcastEp = new IPEndPoint(IPAddress.Broadcast, DhcpClientPort);
                await udp.SendAsync(replyPacket, replyPacket.Length, broadcastEp).ConfigureAwait(false);

                var lease = new DhcpLeaseInfo(assignedIp.ToString(), mac, string.IsNullOrWhiteSpace(hostname) ? $"Client-{assignedIp.GetAddressBytes()[3]}" : hostname, DateTime.UtcNow);
                _leasesByMac[mac] = lease;

                if (msgType == 3)
                {
                    LeaseAssigned?.Invoke(lease);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(50, ct).ConfigureAwait(false);
            }
        }
    }

    private IPAddress AllocateIpForMac(string mac, byte[] chaddr, IPAddress? requestedIp)
    {
        if (_leasesByMac.TryGetValue(mac, out var existing) && IPAddress.TryParse(existing.IpAddress, out var prevIp))
        {
            return prevIp;
        }

        byte[] serverBytes = _serverIp.GetAddressBytes();

        // If client requested an IP on the same /24 subnet (and not .1 or server IP), honor it
        if (requestedIp != null && requestedIp.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] reqBytes = requestedIp.GetAddressBytes();
            if (reqBytes[0] == serverBytes[0] &&
                reqBytes[1] == serverBytes[1] &&
                reqBytes[2] == serverBytes[2] &&
                reqBytes[3] > 2 && reqBytes[3] < 250 &&
                reqBytes[3] != serverBytes[3])
            {
                return requestedIp;
            }
        }

        // Deterministic pool allocation in .150 - .199
        int hash = (chaddr[3] * 31 + chaddr[4] * 17 + chaddr[5]) & 0x7FFFFFFF;
        int hostOctet = 150 + (hash % 50);
        if (hostOctet == serverBytes[3]) hostOctet = hostOctet < 199 ? hostOctet + 1 : 150;

        return new IPAddress(new byte[] { serverBytes[0], serverBytes[1], serverBytes[2], (byte)hostOctet });
    }

    private byte[] BuildDhcpReply(byte[] xid, byte[] chaddr, IPAddress yourIp, byte dhcpMsgType)
    {
        var pkt = new byte[340];
        pkt[0] = BootReply;
        pkt[1] = 1; // Ethernet 10Mb
        pkt[2] = 6; // 6-byte MAC
        pkt[3] = 0; // Hops

        Buffer.BlockCopy(xid, 0, pkt, 4, 4);

        // Flags: Broadcast (0x8000)
        pkt[10] = 0x80;
        pkt[11] = 0x00;

        // yiaddr (Your IP address) at offset 16
        byte[] yi = yourIp.GetAddressBytes();
        Buffer.BlockCopy(yi, 0, pkt, 16, 4);

        // siaddr (Next server IP) at offset 20
        byte[] si = _serverIp.GetAddressBytes();
        Buffer.BlockCopy(si, 0, pkt, 20, 4);

        // chaddr (Client MAC) at offset 28
        Buffer.BlockCopy(chaddr, 0, pkt, 28, 6);

        // Magic Cookie at offset 236
        pkt[236] = 99;
        pkt[237] = 130;
        pkt[238] = 83;
        pkt[239] = 99;

        int o = 240;

        // Option 53: DHCP Message Type
        pkt[o++] = 53;
        pkt[o++] = 1;
        pkt[o++] = dhcpMsgType;

        // Option 54: Server Identifier (Spectra PC IP)
        pkt[o++] = 54;
        pkt[o++] = 4;
        Buffer.BlockCopy(si, 0, pkt, o, 4);
        o += 4;

        // Option 51: Lease Time (86400 seconds = 24 hours)
        pkt[o++] = 51;
        pkt[o++] = 4;
        pkt[o++] = 0x00;
        pkt[o++] = 0x01;
        pkt[o++] = 0x51;
        pkt[o++] = 0x80;

        // Option 1: Subnet Mask
        byte[] mask = _subnetMask.GetAddressBytes();
        pkt[o++] = 1;
        pkt[o++] = 4;
        Buffer.BlockCopy(mask, 0, pkt, o, 4);
        o += 4;

        // Option 3: Router / Default Gateway = Spectra PC IP
        pkt[o++] = 3;
        pkt[o++] = 4;
        Buffer.BlockCopy(si, 0, pkt, o, 4);
        o += 4;

        // Option 6: DNS Server = Spectra PC IP
        pkt[o++] = 6;
        pkt[o++] = 4;
        Buffer.BlockCopy(si, 0, pkt, o, 4);
        o += 4;

        // Option 252: WPAD Proxy Auto-Config URL
        byte[] wpadBytes = Encoding.ASCII.GetBytes($"http://{_serverIp}:{_proxyPort}/wpad.dat");
        pkt[o++] = 252;
        pkt[o++] = (byte)wpadBytes.Length;
        Buffer.BlockCopy(wpadBytes, 0, pkt, o, wpadBytes.Length);
        o += wpadBytes.Length;

        // Option 255: End
        pkt[o++] = 255;

        return pkt[..o];
    }

    private static bool TryDetectLanInterface(out IPAddress ip, out IPAddress mask)
    {
        ip = IPAddress.Parse("192.168.178.203");
        mask = IPAddress.Parse("255.255.255.0");
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                var props = ni.GetIPProperties();
                if (!props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork))
                    continue;

                foreach (var uni in props.UnicastAddresses)
                {
                    if (uni.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(uni.Address))
                    {
                        ip = uni.Address;
                        if (uni.IPv4Mask != null && !uni.IPv4Mask.Equals(IPAddress.Any))
                            mask = uni.IPv4Mask;
                        return true;
                    }
                }
            }
        }
        catch { }
        return false;
    }

    public void Dispose()
    {
        Stop();
    }
}
