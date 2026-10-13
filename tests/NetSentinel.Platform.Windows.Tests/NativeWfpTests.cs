using NetSentinel.Core;
using Windows.Win32;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;
using Xunit;

namespace NetSentinel.Platform.Windows.Tests;

public class NativeWfpTests
{
    [Fact]
    public void FwpmEngineOpen_SucceedsOrRequiresElevation()
    {
        uint error = PInvoke.FwpmEngineOpen0(
            authnService: 0xFFFFFFFF, // RPC_C_AUTHN_DEFAULT
            authIdentity: null,
            session: null,
            out var engineHandle);

        // If running elevated: returns 0 (ERROR_SUCCESS).
        // If not elevated: returns 0x8032000D (FWP_E_ACCESS_DENIED) or 5 (ERROR_ACCESS_DENIED).
        if (error == 0)
        {
            Assert.False(engineHandle.IsInvalid);
            engineHandle.Dispose();
        }
        else
        {
            Assert.True(error == 5 || error == 0x8032000D || error == 0x80070005);
        }
    }

    [Fact]
    public void NativeWfpBlockEventSubscriber_InitializesAndDisposesCleanly()
    {
        using var subscriber = new NativeWfpBlockEventSubscriber();

        // Must not throw whether running elevated or not
        Assert.NotNull(subscriber);

        try
        {
            var recent = subscriber.ReadRecent(TimeSpan.FromSeconds(10), 10);
            Assert.NotNull(recent);
        }
        catch (UnauthorizedAccessException)
        {
            // Expected on non-elevated environments when falling back to wevtutil
        }

        try
        {
            var after = subscriber.ReadAfter(0, 10);
            Assert.NotNull(after);
        }
        catch (UnauthorizedAccessException)
        {
            // Expected on non-elevated environments when falling back to wevtutil
        }
    }
}
