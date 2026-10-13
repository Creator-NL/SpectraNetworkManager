namespace NetSentinel.Core;

/// <summary>Programs the app refuses to block, because blocking them can break Windows or switch off your protection.</summary>
public static class ProtectedPrograms
{
    /// <summary>Folders whose programs are treated as part of Windows / its security.</summary>
    public static IReadOnlyList<string> DefaultFolders()
    {
        var folders = new List<string>();
        void Add(string? p) { if (!string.IsNullOrWhiteSpace(p)) folders.Add(p); }

        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        Add(windows);
        if (programData.Length > 0)
        {
            Add(System.IO.Path.Combine(programData, "Microsoft", "Windows Defender"));
            Add(System.IO.Path.Combine(programData, "Microsoft", "Windows Defender Advanced Threat Protection"));
        }
        foreach (var pf in new[] { programFiles, programFilesX86 })
        {
            if (pf.Length == 0) continue;
            Add(System.IO.Path.Combine(pf, "Windows Defender"));
            Add(System.IO.Path.Combine(pf, "Windows Defender Advanced Threat Protection"));
        }
        return folders;
    }

    public static bool IsProtected(string? path, SignatureInfo? signature, out string reason) =>
        IsProtected(path, DefaultFolders(), signature, out reason);

    public static bool IsProtected(string? path, IEnumerable<string> protectedFolders, SignatureInfo? signature, out string reason)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            reason = "The program's file path is unknown. Run NetSentinel as Administrator so Windows reveals it.";
            return true;
        }

        foreach (var folder in protectedFolders)
        {
            string prefix = folder.TrimEnd('\\', '/') + "\\";
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                reason = "This is part of Windows or its security (system programs, updates, Windows Defender). Blocking it from here is disabled because it can break Windows or switch off your protection.";
                return true;
            }
        }

        if (signature is { Status: SignatureStatus.Valid, IsOsBinary: true })
        {
            reason = "This file is signed as part of Windows itself. Blocking it from here is disabled because it can break Windows.";
            return true;
        }

        reason = "";
        return false;
    }
}
