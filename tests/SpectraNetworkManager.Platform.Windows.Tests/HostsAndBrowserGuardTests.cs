using SpectraNetworkManager.Platform.Windows;
using Xunit;

namespace SpectraNetworkManager.Platform.Windows.Tests;

public sealed class HostsAndBrowserGuardTests
{
    [Fact]
    public void HostsFileMonitor_GetsStatusWithoutThrowing()
    {
        var monitor = new HostsFileMonitor();
        var status = monitor.GetStatus();

        Assert.NotNull(status);
        Assert.NotNull(status.SuspiciousEntries);
        Assert.NotNull(status.ActiveEntries);
    }

    [Fact]
    public void BrowserDohGuard_ReturnsStatusValid()
    {
        var status = BrowserDohGuard.GetStatus();
        Assert.NotNull(status);
        Assert.NotNull(status.Details);
    }
}
