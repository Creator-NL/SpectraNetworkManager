using System.Diagnostics;
using System.Runtime.Versioning;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

[SupportedOSPlatform("windows")]
public sealed class WindowsPktmonCaptureProvider : IPacketCaptureProvider
{
    private static readonly string PktmonPath = Path.Combine(Environment.SystemDirectory, "pktmon.exe");

    private Process? _pktmonProcess;
    private readonly WindowsRawSocketCaptureProvider _fallbackProvider;
    private bool _isUsingPktmon;

    public event Action<CapturedPacket>? PacketCaptured;
    public event Action<string>? StatusChanged;

    public string ProviderName => _isUsingPktmon ? "Windows Pktmon (NDIS Kernel ETW)" : _fallbackProvider.ProviderName;
    public bool IsRunning => _isUsingPktmon ? (_pktmonProcess != null && !_pktmonProcess.HasExited) : _fallbackProvider.IsRunning;

    public static bool IsPktmonAvailable => File.Exists(PktmonPath);

    public WindowsPktmonCaptureProvider(Action<CapturedPacket>? processEnricher = null)
    {
        _fallbackProvider = new WindowsRawSocketCaptureProvider(processEnricher);
        _fallbackProvider.PacketCaptured += p => PacketCaptured?.Invoke(p);
        _fallbackProvider.StatusChanged += s => StatusChanged?.Invoke(s);
    }

    public async Task<bool> StartAsync(string? interfaceIp = null, CancellationToken ct = default)
    {
        if (IsRunning) return true;

        // Try raw socket capture first as it provides instant in-memory C# streaming
        bool rawOk = await _fallbackProvider.StartAsync(interfaceIp, ct);
        if (rawOk)
        {
            _isUsingPktmon = false;
            return true;
        }

        // If raw socket fails, check if pktmon is available
        if (IsPktmonAvailable)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = PktmonPath,
                    Arguments = "start --etw",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                _pktmonProcess = Process.Start(psi);
                if (_pktmonProcess != null)
                {
                    _isUsingPktmon = true;
                    StatusChanged?.Invoke("Started Windows Pktmon driver capture session.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogWarn($"WindowsPktmonCaptureProvider start failed: {ex.Message}");
            }
        }

        StatusChanged?.Invoke("Could not start packet capture. (Requires Administrator privileges)");
        return false;
    }

    public async Task StopAsync()
    {
        if (_isUsingPktmon)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = PktmonPath,
                    Arguments = "stop",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p != null) await p.WaitForExitAsync();
            }
            catch { }
            _pktmonProcess?.Dispose();
            _pktmonProcess = null;
            _isUsingPktmon = false;
            StatusChanged?.Invoke("Pktmon capture stopped.");
        }
        else
        {
            await _fallbackProvider.StopAsync();
        }
    }

    /// <summary>
    /// Uses native pktmon.exe to convert an existing Windows ETL trace to a standard PCAPNG file.
    /// </summary>
    public static async Task<bool> ConvertEtlToPcapngAsync(string etlPath, string pcapngPath)
    {
        if (!IsPktmonAvailable || !File.Exists(etlPath)) return false;

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = PktmonPath,
                Arguments = $"pcapng \"{etlPath}\" -o \"{pcapngPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            await proc.WaitForExitAsync();
            return proc.ExitCode == 0 && File.Exists(pcapngPath);
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogError("Pktmon ETL to PCAPNG conversion failed", ex);
            return false;
        }
    }

    public void Dispose()
    {
        _ = StopAsync();
        _fallbackProvider.Dispose();
    }
}
