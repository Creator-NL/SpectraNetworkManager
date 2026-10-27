using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SpectraNetworkManager.Core;

public static class WellKnownPorts
{
    public static readonly int[] Top20 =
    {
        21,   // FTP
        22,   // SSH
        23,   // Telnet
        25,   // SMTP
        53,   // DNS
        80,   // HTTP
        110,  // POP3
        135,  // MS RPC
        139,  // NetBIOS
        143,  // IMAP
        443,  // HTTPS
        445,  // Microsoft SMB
        993,  // IMAPS
        995,  // POP3S
        1433, // MS SQL
        3306, // MySQL
        3389, // MS RDP
        5900, // VNC
        8080, // HTTP-Proxy / Alt
        8443, // HTTPS-Alt
    };

    public static readonly int[] Top100 =
    {
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
        139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
        646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
        2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5555, 5631, 5666, 5800, 5900,
        6000, 6001, 6646, 7000, 7070, 8000, 8008, 8009, 8060, 8080, 8081, 8443, 8888, 9000, 9100, 9999, 10000, 32400, 49152, 49153
    };

    private static readonly Dictionary<int, string> Services = new()
    {
        { 20, "FTP-Data" },
        { 21, "FTP" },
        { 22, "SSH" },
        { 23, "Telnet" },
        { 25, "SMTP" },
        { 53, "DNS" },
        { 67, "DHCP-Server" },
        { 68, "DHCP-Client" },
        { 69, "TFTP" },
        { 80, "HTTP" },
        { 81, "HTTP-Alt" },
        { 88, "Kerberos" },
        { 110, "POP3" },
        { 111, "RPCBind" },
        { 123, "NTP" },
        { 135, "MS-RPC" },
        { 137, "NetBIOS-Name" },
        { 138, "NetBIOS-Dgm" },
        { 139, "NetBIOS-SSN" },
        { 143, "IMAP" },
        { 161, "SNMP" },
        { 389, "LDAP" },
        { 443, "HTTPS" },
        { 445, "SMB / Microsoft-DS" },
        { 465, "SMTPS" },
        { 500, "IPSec / IKE" },
        { 514, "Syslog" },
        { 515, "LPD / Printer" },
        { 548, "AFP / AppleShare" },
        { 554, "RTSP" },
        { 587, "SMTP-Submission" },
        { 631, "IPP / CUPS Printing" },
        { 636, "LDAPS" },
        { 873, "Rsync" },
        { 993, "IMAPS" },
        { 995, "POP3S" },
        { 1194, "OpenVPN" },
        { 1433, "Microsoft SQL Server" },
        { 1521, "Oracle DB" },
        { 1723, "PPTP" },
        { 1883, "MQTT (IoT)" },
        { 1900, "SSDP / UPnP" },
        { 2049, "NFS" },
        { 2375, "Docker (HTTP)" },
        { 2376, "Docker (HTTPS)" },
        { 3000, "Node / Dev Web" },
        { 3306, "MySQL" },
        { 3389, "RDP / Remote Desktop" },
        { 5000, "UPnP / Synology" },
        { 5060, "SIP (VoIP)" },
        { 5353, "mDNS" },
        { 5357, "WSDAPI / Web Services" },
        { 5432, "PostgreSQL" },
        { 5555, "Android ADB / Fire TV" },
        { 5900, "VNC Remote Access" },
        { 7000, "AirPlay Receiver" },
        { 8000, "HTTP-Alt" },
        { 8008, "Google Cast HTTP" },
        { 8009, "Google Cast V2" },
        { 8060, "Roku ECP (External Control)" },
        { 8080, "HTTP-Proxy / Alt" },
        { 8081, "HTTP-Alt" },
        { 8443, "HTTPS-Alt" },
        { 8888, "HTTP-Alt" },
        { 9000, "Portainer / Web" },
        { 9100, "JetDirect / RAW Print" },
        { 32400, "Plex Media Server" },
    };

    public static string GetServiceName(int port, Protocol protocol)
    {
        if (Services.TryGetValue(port, out string? name)) return name;
        return protocol == Protocol.Udp ? $"UDP/{port}" : $"TCP/{port}";
    }

    public static async Task<string> TryGrabBannerAsync(IPAddress ip, int port, int timeoutMs = 300)
    {
        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            using var client = new TcpClient();
            await client.ConnectAsync(ip, port, cts.Token);

            var stream = client.GetStream();
            stream.ReadTimeout = timeoutMs;
            stream.WriteTimeout = timeoutMs;

            byte[] buffer = new byte[256];

            // If HTTP or HTTPS, send a minimal HEAD request
            if (port is 80 or 8080 or 8000 or 8081 or 8060 or 5000)
            {
                byte[] req = "HEAD / HTTP/1.0\r\n\r\n"u8.ToArray();
                await stream.WriteAsync(req, cts.Token);
            }

            int read = await stream.ReadAsync(buffer, cts.Token);
            if (read > 0)
            {
                string text = Encoding.ASCII.GetString(buffer, 0, read).Trim();
                var firstLine = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(firstLine))
                {
                    if (firstLine.Length > 60) firstLine = firstLine[..60] + "…";
                    return firstLine;
                }
            }
        }
        catch
        {
            // Best effort banner grabbing
        }
        return "";
    }
}
