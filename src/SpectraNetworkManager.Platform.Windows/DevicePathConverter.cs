using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace SpectraNetworkManager.Platform.Windows;

/// <summary>Turns kernel paths like \device\harddiskvolume3\windows\x.exe into C:\windows\x.exe.</summary>
[SupportedOSPlatform("windows")]
internal sealed class DevicePathConverter
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string deviceName, StringBuilder target, uint max);

    private readonly List<(string Device, string Drive)> _map = new();

    public DevicePathConverter()
    {
        for (char letter = 'A'; letter <= 'Z'; letter++)
        {
            var sb = new StringBuilder(512);
            string drive = $"{letter}:";
            if (QueryDosDeviceW(drive, sb, (uint)sb.Capacity) > 0)
                _map.Add((sb.ToString(), drive));
        }
    }

    public string ToDosPath(string path)
    {
        foreach (var (device, drive) in _map)
            if (path.StartsWith(device, StringComparison.OrdinalIgnoreCase)
                && (path.Length == device.Length || path[device.Length] == '\\'))
                return drive + path[device.Length..];
        return path;
    }
}
