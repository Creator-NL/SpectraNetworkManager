using System.Collections;
using System.Runtime.Versioning;
using SpectraNetworkManager.Core.Devices;

namespace SpectraNetworkManager.Platform.Windows;

/// <summary>
/// Reads and changes the Windows network location (Public / Private) of the networks you are connected to.
/// Works for cable and Wi-Fi. Uses the built-in Network List Manager COM object.
/// </summary>
[SupportedOSPlatform("windows")]
public static class NetworkProfileInspector
{
    private static readonly Guid NetworkListManagerClsid = new("DCB00C01-570F-4A9B-8D69-199FDBA5723B");
    private const int EnumConnected = 1;

    /// <summary>Lists the networks Windows is connected to right now. Returns an empty list if Windows refuses.</summary>
    public static IReadOnlyList<NetworkProfileInfo> GetConnectedNetworks()
    {
        var result = new List<NetworkProfileInfo>();
        try
        {
            dynamic? manager = CreateManager();
            if (manager is null) return result;

            foreach (dynamic network in (IEnumerable)manager.GetNetworks(EnumConnected))
            {
                string name = (string)network.GetName();
                int category = (int)network.GetCategory();
                var kind = Enum.IsDefined(typeof(NetworkCategoryKind), category)
                    ? (NetworkCategoryKind)category
                    : NetworkCategoryKind.Public;
                result.Add(new NetworkProfileInfo(name, kind));
            }
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            // Not fatal: the caller simply shows no network warning.
        }

        return result;
    }

    /// <summary>Switches every connected Public network to Private. Needs Administrator. Returns how many were changed.</summary>
    public static int SetPublicNetworksToPrivate(out string error)
    {
        error = "";
        int changed = 0;
        try
        {
            dynamic? manager = CreateManager();
            if (manager is null)
            {
                error = "Windows network list manager is not available.";
                return 0;
            }

            foreach (dynamic network in (IEnumerable)manager.GetNetworks(EnumConnected))
            {
                if ((int)network.GetCategory() == (int)NetworkCategoryKind.Public)
                {
                    network.SetCategory((int)NetworkCategoryKind.Private);
                    changed++;
                }
            }
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or UnauthorizedAccessException or InvalidOperationException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            error = ex.Message;
        }

        return changed;
    }

    private static object? CreateManager()
    {
        var type = Type.GetTypeFromCLSID(NetworkListManagerClsid);
        return type is null ? null : Activator.CreateInstance(type);
    }
}
