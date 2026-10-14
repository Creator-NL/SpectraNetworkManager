using System.Diagnostics;

namespace SpectraNetworkManager.Engine;

public static class ServiceInstaller
{
    public const string ServiceName = "SpectraNetworkManager.Engine";
    public const string DisplayName = "SpectraNetworkManager Engine";
    public const string Description = "SpectraNetworkManager background network monitor, firewall enforcer, and DNS sinkhole service.";

    public static async Task<int> InstallAsync()
    {
        string? exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
        {
            Console.Error.WriteLine("Could not determine current executable path.");
            return 1;
        }

        string binPath = $"\"{exePath}\" --service";
        Console.WriteLine($"Registering service '{ServiceName}'...");

        int exitCode = await RunScAsync($"create \"{ServiceName}\" binPath= \"{binPath}\" start= delayed-auto DisplayName= \"{DisplayName}\"");
        if (exitCode != 0)
        {
            Console.Error.WriteLine($"Failed to create service (sc exit code {exitCode}). Ensure running as Administrator.");
            return exitCode;
        }

        await RunScAsync($"description \"{ServiceName}\" \"{Description}\"");
        await RunScAsync($"failure \"{ServiceName}\" reset= 86400 actions= restart/5000/restart/10000/restart/30000");

        Console.WriteLine($"Service '{ServiceName}' registered successfully.");
        Console.WriteLine("To start: net start SpectraNetworkManager.Engine");
        return 0;
    }

    public static async Task<int> UninstallAsync()
    {
        Console.WriteLine($"Stopping and removing service '{ServiceName}'...");
        await RunScAsync($"stop \"{ServiceName}\"");
        int exitCode = await RunScAsync($"delete \"{ServiceName}\"");

        try { await RunScAsync("stop \"NetSentinel.Engine\""); } catch { }
        try { await RunScAsync("delete \"NetSentinel.Engine\""); } catch { }

        if (exitCode == 0)
        {
            Console.WriteLine($"Service '{ServiceName}' uninstalled successfully.");
        }
        else
        {
            Console.Error.WriteLine($"Failed to delete service (sc exit code {exitCode}).");
        }
        return exitCode;
    }

    private static async Task<int> RunScAsync(string args)
    {
        var psi = new ProcessStartInfo("sc.exe", args)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        if (process == null) return -1;

        await process.WaitForExitAsync().ConfigureAwait(false);
        return process.ExitCode;
    }
}
