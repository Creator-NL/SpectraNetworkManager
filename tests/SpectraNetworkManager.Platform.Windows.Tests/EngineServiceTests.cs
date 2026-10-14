using System.Runtime.Versioning;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Core.Ipc;
using SpectraNetworkManager.Engine;
using Xunit;

namespace SpectraNetworkManager.Platform.Windows.Tests;

[SupportedOSPlatform("windows")]
public class EngineServiceTests
{
    [Fact]
    public async Task EngineCoordinator_StartsInSafeMode_AndAnswersPingOverIpc()
    {
        await using var coordinator = new EngineCoordinator(safeMode: true);
        await coordinator.StartAsync();

        await using var client = new IpcClient(IpcConstants.PipeName);
        await client.ConnectAsync(TimeSpan.FromSeconds(3));

        var pingResponse = await client.SendRequestAsync(IpcConstants.Actions.Ping, null, TimeSpan.FromSeconds(3));

        Assert.NotNull(pingResponse);
        Assert.True(pingResponse.Success);
        Assert.Contains("OK", pingResponse.PayloadJson ?? "");
    }

    [Fact]
    public async Task EngineCoordinator_ReturnsEngineStatus_OverIpc()
    {
        await using var coordinator = new EngineCoordinator(safeMode: true);
        await coordinator.StartAsync();

        await using var client = new IpcClient(IpcConstants.PipeName);
        await client.ConnectAsync(TimeSpan.FromSeconds(3));

        var statusResponse = await client.SendRequestAsync(IpcConstants.Actions.GetEngineStatus, null, TimeSpan.FromSeconds(3));

        Assert.NotNull(statusResponse);
        Assert.True(statusResponse.Success);
        Assert.Contains("safeMode", statusResponse.PayloadJson ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Contains("clientCount", statusResponse.PayloadJson ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EngineCoordinator_AddRuleAndGetRules_OverIpc()
    {
        await using var coordinator = new EngineCoordinator(safeMode: true);
        await coordinator.StartAsync();

        await using var client = new IpcClient(IpcConstants.PipeName);
        await client.ConnectAsync(TimeSpan.FromSeconds(3));

        var rule = new ProgramRule(
            @"C:\Test\EngineDummyApp.exe",
            RuleAction.Block,
            DateTimeOffset.UtcNow,
            "Engine IPC test rule",
            RuleDirection.Outbound,
            TrafficScope.All);

        var addResp = await client.SendRequestAsync(IpcConstants.Actions.AddRule, rule, TimeSpan.FromSeconds(3));
        Assert.True(addResp.Success);

        var getResp = await client.SendRequestAsync(IpcConstants.Actions.GetRules, null, TimeSpan.FromSeconds(3));
        Assert.True(getResp.Success);
        Assert.Contains("EngineDummyApp.exe", getResp.PayloadJson ?? "");

        // Cleanup
        await client.SendRequestAsync(IpcConstants.Actions.RemoveRule, rule.Path, TimeSpan.FromSeconds(3));
    }
}
