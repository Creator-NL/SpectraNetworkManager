using System;
using System.Threading;
using System.Threading.Tasks;
using SpectraNetworkManager.Core.BrowserGuard;
using SpectraNetworkManager.Platform.Windows.BrowserGuard;

namespace SpectraNetworkManager.BrowserHost;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var guardManager = new BrowserGuardManager();
        using var cts = new CancellationTokenSource();
        await BrowserExtensionHost.RunStdioLoopAsync(guardManager, cts.Token);
        return 0;
    }
}
