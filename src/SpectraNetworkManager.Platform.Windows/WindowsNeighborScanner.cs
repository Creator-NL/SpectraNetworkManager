using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

[SupportedOSPlatform("windows")]
public sealed class WindowsNeighborScanner : INeighborScanner
{
    public IReadOnlyList<(IPAddress Ip, string Mac, bool IsGateway)> GetNeighborTable()
    {
        var list = new List<(IPAddress Ip, string Mac, bool IsGateway)>();

        // 1. Try native P/Invoke GetIpNetTable
        try
        {
            int size = 0;
            NativeMethods.GetIpNetTable(IntPtr.Zero, ref size, false);
            if (size > 0 && size < 1048576)
            {
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint status = NativeMethods.GetIpNetTable(buffer, ref size, false);
                    if (status == NativeMethods.NoError)
                    {
                        int count = Marshal.ReadInt32(buffer);
                        IntPtr current = IntPtr.Add(buffer, 4);
                        int rowSize = Marshal.SizeOf<NativeMethods.MibIpNetRow>();

                        for (int i = 0; i < count; i++)
                        {
                            var row = Marshal.PtrToStructure<NativeMethods.MibIpNetRow>(current);
                            if (row.PhysAddrLen == 6 && row.PhysAddr != null)
                            {
                                var ip = new IPAddress((long)row.Addr & 0xFFFFFFFF);
                                string mac = string.Join("-", row.PhysAddr.Take(6).Select(b => b.ToString("X2")));

                                // Type 3 = Dynamic, 4 = Static
                                if (row.Type is 3 or 4 && IsValidLanHost(ip, mac))
                                {
                                    list.Add((ip, mac, false));
                                }
                            }
                            current = IntPtr.Add(current, rowSize);
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
        catch
        {
            // Fallback below
        }

        // 2. If native call yielded nothing, fallback to parsing 'arp -a'
        if (list.Count == 0)
        {
            try
            {
                var psi = new ProcessStartInfo("arp.exe", "-a")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p != null)
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(1000);

                    // Lines like:  192.168.1.1       00-11-22-33-44-55     dynamic
                    var regex = new Regex(@"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})\s+(dynamic|static)", RegexOptions.IgnoreCase);
                    var matches = regex.Matches(output);
                    foreach (Match m in matches)
                    {
                        if (IPAddress.TryParse(m.Groups[1].Value, out var ip))
                        {
                            string mac = m.Groups[2].Value.ToUpperInvariant();
                            if (IsValidLanHost(ip, mac))
                            {
                                list.Add((ip, mac, false));
                            }
                        }
                    }
                }
            }
            catch
            {
                // Best effort
            }
        }

        return list;
    }

    private static bool IsValidLanHost(IPAddress ip, string mac)
    {
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.None) || ip.Equals(IPAddress.Broadcast))
            return false;

        byte[] b = ip.GetAddressBytes();
        if (b.Length == 4)
        {
            // Multicast range 224.0.0.0 to 239.255.255.255 (Class D)
            if (b[0] >= 224 && b[0] <= 239)
                return false;
            // Reserved / Experimental range 240.0.0.0 to 255.255.255.255 (Class E)
            if (b[0] >= 240)
                return false;
            // 0.0.0.0/8
            if (b[0] == 0)
                return false;
            // Subnet broadcast ending in 255
            if (b[3] == 255)
                return false;
        }

        // Multicast MAC addresses (starts with 01-00-5E or 33-33)
        if (mac.StartsWith("01-00-5E", StringComparison.OrdinalIgnoreCase) ||
            mac.StartsWith("33-33", StringComparison.OrdinalIgnoreCase) ||
            mac.StartsWith("FF-FF-FF", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    public Task<string?> ProbeMacAddressAsync(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return Task.FromResult<string?>(null);

        return Task.Run(() =>
        {
            try
            {
                byte[] b = ip.GetAddressBytes();
                uint destIp = BitConverter.ToUInt32(b, 0);
                byte[] macBytes = new byte[6];
                int macLen = macBytes.Length;

                int ret = NativeMethods.SendARP(destIp, 0, macBytes, ref macLen);
                if (ret == 0 && macLen == 6)
                {
                    return string.Join("-", macBytes.Select(x => x.ToString("X2")));
                }
            }
            catch
            {
                // Best effort
            }
            return null;
        });
    }
}
