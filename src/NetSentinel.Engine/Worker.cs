using Microsoft.Extensions.Hosting;

namespace NetSentinel.Engine;

public sealed class Worker : BackgroundService
{
    private readonly EngineCoordinator _coordinator;

    public Worker(EngineCoordinator coordinator)
    {
        _coordinator = coordinator;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Console.WriteLine("[NetSentinel.Engine] Service worker starting...");
        await _coordinator.StartAsync(stoppingToken);

        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        finally
        {
            Console.WriteLine("[NetSentinel.Engine] Service worker stopping...");
            await _coordinator.DisposeAsync();
        }
    }
}
