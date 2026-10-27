using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SpectraNetworkManager.Engine;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        Console.WriteLine("SpectraNetworkManager Background Engine Service");
        Console.WriteLine("=====================================");

        if (args.Contains("--install", StringComparer.OrdinalIgnoreCase))
        {
            return await ServiceInstaller.InstallAsync();
        }

        if (args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase))
        {
            return await ServiceInstaller.UninstallAsync();
        }

        if (args.Contains("--browser-host", StringComparer.OrdinalIgnoreCase))
        {
            var guardManager = new SpectraNetworkManager.Core.BrowserGuard.BrowserGuardManager();
            using var cts = new CancellationTokenSource();
            await SpectraNetworkManager.Platform.Windows.BrowserGuard.BrowserExtensionHost.RunStdioLoopAsync(guardManager, cts.Token);
            return 0;
        }

        bool isService = args.Contains("--service", StringComparer.OrdinalIgnoreCase);
        bool safeMode = args.Contains("--safe", StringComparer.OrdinalIgnoreCase);

        if (safeMode)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[WARN] Starting in SAFE MODE (enforcement disarmed).");
            Console.ResetColor();
        }

        var builder = Host.CreateDefaultBuilder(args);

        if (isService)
        {
            builder.UseWindowsService(options =>
            {
                options.ServiceName = ServiceInstaller.ServiceName;
            });
        }

        builder.ConfigureServices(services =>
        {
            services.AddSingleton(new EngineCoordinator(safeMode));
            services.AddHostedService<Worker>();
        });

        var host = builder.Build();
        await host.RunAsync();
        return 0;
    }
}
