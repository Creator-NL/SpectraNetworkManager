using System;
using System.IO;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using SpectraNetworkManager.Core.BrowserGuard;

namespace SpectraNetworkManager.Platform.Windows.BrowserGuard;

/// <summary>
/// Implements the Chrome, Edge, and Firefox standard Native Messaging Host protocol
/// and Windows Registry registration for the Spectra Browser Guard extension.
/// </summary>
[SupportedOSPlatform("windows")]
public static class BrowserExtensionHost
{
    private static readonly JsonSerializerOptions IndentedJsonOpts = new() { WriteIndented = true };

    public const string HostName = "com.spectranetworkmanager.browser_host";
    public const string ChromeExtensionId = "kndcdcampgmfjgniielafdiblkfhdklk";
    public const string FirefoxExtensionId = "browserguard@spectranetworkmanager.com";

    /// <summary>
    /// Registers the Native Messaging Host in current user's registry for Chrome, Edge, and Firefox.
    /// </summary>
    public static bool RegisterHost(string hostExePath, out string error)
    {
        error = "";
        try
        {
            string hostDir = Path.GetDirectoryName(hostExePath)!;
            string chromeManifestPath = Path.Combine(hostDir, $"{HostName}.chrome.json");
            string firefoxManifestPath = Path.Combine(hostDir, $"{HostName}.firefox.json");

            // 1. Chrome / Edge manifest (uses exact deterministic extension ID derived from manifest.json 'key')
            var chromeManifest = new
            {
                name = HostName,
                description = "Spectra Browser Guard Host for Chrome and Edge",
                path = hostExePath,
                type = "stdio",
                allowed_origins = new[]
                {
                    $"chrome-extension://{ChromeExtensionId}/"
                }
            };
            File.WriteAllText(chromeManifestPath, JsonSerializer.Serialize(chromeManifest, IndentedJsonOpts));

            // 2. Firefox manifest (uses allowed_extensions)
            var firefoxManifest = new
            {
                name = HostName,
                description = "Spectra Browser Guard Host for Mozilla Firefox",
                path = hostExePath,
                type = "stdio",
                allowed_extensions = new[]
                {
                    FirefoxExtensionId
                }
            };
            File.WriteAllText(firefoxManifestPath, JsonSerializer.Serialize(firefoxManifest, IndentedJsonOpts));

            // 3. Register in Chrome registry
            using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Google\Chrome\NativeMessagingHosts\{HostName}"))
            {
                k?.SetValue("", chromeManifestPath, RegistryValueKind.String);
            }

            // 4. Register in Chromium registry
            using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Chromium\NativeMessagingHosts\{HostName}"))
            {
                k?.SetValue("", chromeManifestPath, RegistryValueKind.String);
            }

            // 5. Register in Edge registry
            using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Microsoft\Edge\NativeMessagingHosts\{HostName}"))
            {
                k?.SetValue("", chromeManifestPath, RegistryValueKind.String);
            }

            // 6. Register in Firefox registry
            using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Mozilla\NativeMessagingHosts\{HostName}"))
            {
                k?.SetValue("", firefoxManifestPath, RegistryValueKind.String);
            }

            // 7. Register in Brave registry
            using (var k = Registry.CurrentUser.CreateSubKey($@"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\{HostName}"))
            {
                k?.SetValue("", chromeManifestPath, RegistryValueKind.String);
            }

            // 8. Register in Vivaldi registry
            using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Vivaldi\NativeMessagingHosts\{HostName}"))
            {
                k?.SetValue("", chromeManifestPath, RegistryValueKind.String);
            }

            // 9. Register in Opera registry
            using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Opera Software\Opera Stable\NativeMessagingHosts\{HostName}"))
            {
                k?.SetValue("", chromeManifestPath, RegistryValueKind.String);
            }

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Unregisters the Native Messaging Host from Chrome, Edge, Firefox, Brave, Vivaldi, and Opera.
    /// </summary>
    public static bool UnregisterHost(out string error)
    {
        error = "";
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree($@"Software\Google\Chrome\NativeMessagingHosts\{HostName}", false);
            Registry.CurrentUser.DeleteSubKeyTree($@"Software\Chromium\NativeMessagingHosts\{HostName}", false);
            Registry.CurrentUser.DeleteSubKeyTree($@"Software\Microsoft\Edge\NativeMessagingHosts\{HostName}", false);
            Registry.CurrentUser.DeleteSubKeyTree($@"Software\Mozilla\NativeMessagingHosts\{HostName}", false);
            Registry.CurrentUser.DeleteSubKeyTree($@"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\{HostName}", false);
            Registry.CurrentUser.DeleteSubKeyTree($@"Software\Vivaldi\NativeMessagingHosts\{HostName}", false);
            Registry.CurrentUser.DeleteSubKeyTree($@"Software\Opera Software\Opera Stable\NativeMessagingHosts\{HostName}", false);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Checks whether the Native Messaging Host is registered in the registry.
    /// </summary>
    public static bool IsHostRegistered()
    {
        try
        {
            using var c = Registry.CurrentUser.OpenSubKey($@"Software\Google\Chrome\NativeMessagingHosts\{HostName}");
            using var e = Registry.CurrentUser.OpenSubKey($@"Software\Microsoft\Edge\NativeMessagingHosts\{HostName}");
            using var f = Registry.CurrentUser.OpenSubKey($@"Software\Mozilla\NativeMessagingHosts\{HostName}");
            using var b = Registry.CurrentUser.OpenSubKey($@"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\{HostName}");
            using var v = Registry.CurrentUser.OpenSubKey($@"Software\Vivaldi\NativeMessagingHosts\{HostName}");
            using var o = Registry.CurrentUser.OpenSubKey($@"Software\Opera Software\Opera Stable\NativeMessagingHosts\{HostName}");
            return c != null || e != null || f != null || b != null || v != null || o != null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Runs the stdio message pump for the browser Native Messaging protocol.
    /// Reads 4-byte little-endian message length headers, parses JSON, and replies via stdout.
    /// </summary>
    public static async Task RunStdioLoopAsync(BrowserGuardManager guardManager, CancellationToken ct)
    {
        using var stdin = Console.OpenStandardInput();
        using var stdout = Console.OpenStandardOutput();

        byte[] lengthBuffer = new byte[4];

        while (!ct.IsCancellationRequested)
        {
            // 1. Read 4-byte message length
            int bytesRead = 0;
            while (bytesRead < 4)
            {
                int r = await stdin.ReadAsync(lengthBuffer.AsMemory(bytesRead, 4 - bytesRead), ct);
                if (r == 0) return; // Stdin closed by browser
                bytesRead += r;
            }

            int messageLength = BitConverter.ToInt32(lengthBuffer, 0);
            if (messageLength <= 0 || messageLength > 10 * 1024 * 1024) return; // Malformed length

            // 2. Read UTF-8 payload
            byte[] messageBuffer = new byte[messageLength];
            bytesRead = 0;
            while (bytesRead < messageLength)
            {
                int r = await stdin.ReadAsync(messageBuffer.AsMemory(bytesRead, messageLength - bytesRead), ct);
                if (r == 0) return;
                bytesRead += r;
            }

            string requestJson = Encoding.UTF8.GetString(messageBuffer);

            // 3. Process message
            string responseJson = ProcessNativeMessage(requestJson, guardManager);

            // 4. Send 4-byte length + UTF-8 payload to browser
            byte[] responseBytes = Encoding.UTF8.GetBytes(responseJson);
            byte[] outLength = BitConverter.GetBytes(responseBytes.Length);

            await stdout.WriteAsync(outLength, ct);
            await stdout.WriteAsync(responseBytes, ct);
            await stdout.FlushAsync(ct);
        }
    }

    private static string ProcessNativeMessage(string requestJson, BrowserGuardManager guardManager)
    {
        try
        {
            using var doc = JsonDocument.Parse(requestJson);
            var root = doc.RootElement;
            string type = root.TryGetProperty("type", out var tProp) ? tProp.GetString() ?? "" : "";

            switch (type)
            {
                case "ping":
                    return JsonSerializer.Serialize(new { type = "pong", timestamp = DateTime.UtcNow });

                case "get_rules":
                    guardManager.Load();
                    return JsonSerializer.Serialize(new
                    {
                        type = "rules_update",
                        enabled = guardManager.Config.ExtensionEnabled,
                        blockYouTubeAds = guardManager.Config.BlockYouTubeAds,
                        blockYouTubeAnnotations = guardManager.Config.BlockYouTubeAnnotations,
                        blockYouTubeShorts = guardManager.Config.BlockYouTubeShorts,
                        placeholder = guardManager.Config.ShowInPagePlaceholder,
                        rulesJson = guardManager.ExportMv3DynamicRulesJson(),
                        customRules = guardManager.Config.CustomRules.Where(r => r.Enabled).Select(r => new
                        {
                            id = r.Id,
                            pattern = r.Pattern,
                            title = r.Title,
                            action = r.Action.ToString().ToLowerInvariant(),
                            resourceType = r.ResourceType
                        }).ToList()
                    });

                case "toggle_rule":
                    if (root.TryGetProperty("id", out var idProp) && root.TryGetProperty("enabled", out var enProp))
                    {
                        guardManager.ToggleRule(idProp.GetString()!, enProp.GetBoolean());
                    }
                    return JsonSerializer.Serialize(new { type = "ok" });

                default:
                    return JsonSerializer.Serialize(new { type = "unknown", received = type });
            }
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { type = "error", message = ex.Message });
        }
    }
}
