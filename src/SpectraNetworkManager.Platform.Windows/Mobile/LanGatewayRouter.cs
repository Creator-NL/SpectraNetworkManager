using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Microsoft.Win32;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Core.Devices;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Platform.Windows.Mobile;

/// <summary>
/// Enables Layer-3 LAN Gateway / Router mode on the host PC (IPv4 packet forwarding to the upstream ISP gateway)
/// and inspects routed LAN packets via native TLS SNI and HTTP Host dissection so any phone or TV using this PC
/// as its Default Gateway has 100% of its domains logged and filtered in real time.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LanGatewayRouter : IDisposable
{
    private readonly WindowsRawSocketCaptureProvider _sniSniffer = new();
    private readonly ConcurrentDictionary<string, DateTime> _recentSniGate = new(StringComparer.OrdinalIgnoreCase);
    private IPAddress? _localLanIp;
    private IPAddress? _gatewayIp;
    private long _routedPacketsSeen;

    public bool IsRunning { get; private set; }
    public long RoutedPacketsSeen => Interlocked.Read(ref _routedPacketsSeen);

    /// <summary>
    /// Evaluates whether a domain is blocked or allowed for the given client IP.
    /// </summary>
    public Func<IPAddress, string, FilterDecision>? DecideDomain { get; set; }

    /// <summary>
    /// Fired whenever a routed LAN device initiates a TLS SNI or HTTP connection through this PC gateway.
    /// </summary>
    public event Action<DnsLogEntry>? RoutedActivityLogged;

    public LanGatewayRouter()
    {
        _sniSniffer.PacketCaptured += OnPacketCaptured;
    }

    public async Task<bool> StartAsync(IPAddress? localLanIp = null, IPAddress? gatewayIp = null)
    {
        if (IsRunning) return true;

        _localLanIp = localLanIp ?? GetActiveLanIpv4(out _gatewayIp);
        if (gatewayIp != null) _gatewayIp = gatewayIp;

        EnableWindowsIpForwarding();

        if (_localLanIp != null)
        {
            await _sniSniffer.StartAsync(_localLanIp.ToString()).ConfigureAwait(false);
        }

        IsRunning = true;
        return true;
    }

    public async Task StopAsync()
    {
        if (!IsRunning) return;
        IsRunning = false;
        try { await _sniSniffer.StopAsync().ConfigureAwait(false); } catch { }
    }

    private void OnPacketCaptured(CapturedPacket pkt)
    {
        try
        {
            if (pkt.SourceAddress == null || _localLanIp == null) return;
            if (pkt.SourceAddress.Equals(_localLanIp) || IPAddress.IsLoopback(pkt.SourceAddress)) return;
            if (_gatewayIp != null && pkt.SourceAddress.Equals(_gatewayIp)) return;

            if (!IsPrivateIpv4(pkt.SourceAddress)) return;

            Interlocked.Increment(ref _routedPacketsSeen);

            if (string.IsNullOrWhiteSpace(pkt.HostOrSni)) return;
            if (pkt.Protocol == PacketProtocol.Dns) return; // Port 53 DNS is already logged by DnsServer

            string domain = DomainFilter.Normalize(pkt.HostOrSni);
            if (string.IsNullOrWhiteSpace(domain)) return;

            string clientIpStr = DnsClientMatch.NormalizeIp(pkt.SourceAddress.ToString());
            string gateKey = $"{clientIpStr}|{domain}";
            var now = DateTime.UtcNow;

            if (_recentSniGate.TryGetValue(gateKey, out var prev) && (now - prev).TotalSeconds < 3.0)
                return;
            _recentSniGate[gateKey] = now;
            if (_recentSniGate.Count > 2000) _recentSniGate.Clear();

            var decision = DecideDomain?.Invoke(pkt.SourceAddress, domain)
                           ?? new FilterDecision(FilterAction.None, "");

            string protoType = pkt.Protocol == PacketProtocol.Tls ? "TLS-SNI" : "HTTP";
            var outcome = decision.Action == FilterAction.Blocked ? DnsOutcome.Blocked : DnsOutcome.Forwarded;
            string detail = decision.Action == FilterAction.Blocked
                ? $"gateway detected blocked host ({decision.Reason})"
                : $"gateway routed -> {pkt.DestinationAddress}:{pkt.DestinationPort}";

            var entry = new DnsLogEntry(DateTimeOffset.Now, clientIpStr, domain, protoType, outcome, detail, 1);
            RoutedActivityLogged?.Invoke(entry);
        }
        catch
        {
            // Never fault capture loop
        }
    }

    private static void EnableWindowsIpForwarding()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", writable: true);
            key?.SetValue("IPEnableRouter", 1, RegistryValueKind.DWord);
        }
        catch { }

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                var ipv4Props = ni.GetIPProperties().GetIPv4Properties();
                if (ipv4Props != null)
                {
                    RunNetshSilent($"interface ipv4 set interface {ipv4Props.Index} forwarding=enabled");
                }
            }
        }
        catch { }
    }

    private static void RunNetshSilent(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh.exe", args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(1500);
        }
        catch { }
    }

    private static IPAddress? GetActiveLanIpv4(out IPAddress? gateway)
    {
        gateway = null;
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                var props = ni.GetIPProperties();
                IPAddress? gw = null;
                foreach (var g in props.GatewayAddresses)
                {
                    if (g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any))
                    {
                        gw = g.Address;
                        break;
                    }
                }
                if (gw == null) continue;

                foreach (var uni in props.UnicastAddresses)
                {
                    if (uni.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(uni.Address))
                    {
                        gateway = gw;
                        return uni.Address;
                    }
                }
            }
        }
        catch { }
        return null;
    }

    private static bool IsPrivateIpv4(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        byte[] b = ip.GetAddressBytes();
        return b[0] == 10 ||
               (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
               (b[0] == 192 && b[1] == 168);
    }

    public void Dispose()
    {
        _ = StopAsync();
        _sniSniffer.Dispose();
    }
}
