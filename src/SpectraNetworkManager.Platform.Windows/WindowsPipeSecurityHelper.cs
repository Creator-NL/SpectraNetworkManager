using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace SpectraNetworkManager.Platform.Windows;

public static class WindowsPipeSecurityHelper
{
    public static string SingleInstancePipeName =>
        $"SpectraNetworkManager.App.SingleInstance.{Environment.UserName}.Session{Process.GetCurrentProcess().SessionId}";

    public static bool TrySendSingleInstanceCommand(string command, int timeoutMs = 500)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", SingleInstancePipeName, PipeDirection.Out);
            client.Connect(timeoutMs);
            using var writer = new StreamWriter(client, Encoding.UTF8) { AutoFlush = true };
            writer.WriteLine(command);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static NamedPipeServerStream CreateSecuredServerStream(string pipeName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
        }

        var pipeSecurity = new PipeSecurity();

        var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        pipeSecurity.AddAccessRule(new PipeAccessRule(adminSid, PipeAccessRights.FullControl, AccessControlType.Allow));

        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        pipeSecurity.AddAccessRule(new PipeAccessRule(systemSid, PipeAccessRights.FullControl, AccessControlType.Allow));

        var usersSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        pipeSecurity.AddAccessRule(new PipeAccessRule(usersSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 65536,
            outBufferSize: 65536,
            pipeSecurity);
    }
}
