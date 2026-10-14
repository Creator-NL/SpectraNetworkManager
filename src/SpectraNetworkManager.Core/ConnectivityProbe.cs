namespace SpectraNetworkManager.Core;

public sealed record ProbeResult(bool Ok, string Message);

/// <summary>
/// Checks whether this PC still has working internet, the same way Windows itself does:
/// it fetches Microsoft's tiny "connect test" page. Used to warn you right after strict mode is switched on.
/// </summary>
public static class ConnectivityProbe
{
    public const string Url = "http://www.msftconnecttest.com/connecttest.txt";
    private const string ExpectedBody = "Microsoft Connect Test";

    public static async Task<ProbeResult> RunAsync(HttpMessageHandler? handler = null, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        using var client = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: false);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(8));

        try
        {
            string body = (await client.GetStringAsync(Url, cts.Token).ConfigureAwait(false)).Trim();
            return body == ExpectedBody
                ? new ProbeResult(true, "Internet connection works.")
                : new ProbeResult(false, "A page came back, but not the expected one (a sign-in page or filter in between?).");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new ProbeResult(false, "No answer within a few seconds.");
        }
        catch (Exception ex)
        {
            return new ProbeResult(false, "Could not connect: " + ex.Message);
        }
    }
}
