namespace SpectraNetworkManager.Core;

/// <summary>Programs the app refuses to block, because blocking them can break Windows or switch off your protection.</summary>
public static class ProtectedPrograms
{
    /// <summary>
    /// Shared runtime components, local servers, and core system utilities that must NEVER be subjected to
    /// kernel-level execution lockout (IFEO debugger redirection to systray.exe).
    /// Redirecting these binaries breaks all local dependent applications across the entire operating system
    /// (e.g. WebView2 cache access, local Ollama engine, Windows shell components).
    /// </summary>
    public static readonly HashSet<string> DisallowedExecutionLockoutBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedgewebview2.exe",
        "ollama.exe",
        "ollama_llama_server.exe",
        "ollama app.exe",
        "runtimebroker.exe",
        "explorer.exe",
        "svchost.exe",
        "services.exe",
        "lsass.exe",
        "csrss.exe",
        "smss.exe",
        "sihost.exe",
        "taskhostw.exe",
        "devenv.exe",
        "code.exe",
        "SpectraNetworkManager.exe",
        "SpectraNetworkManager.Engine.exe",
        "SpectraNetworkManager.BrowserHost.exe"
    };

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

    public static bool IsProtected(string? path) =>
        IsProtected(path, DefaultFolders(), null, out _);

    public static bool IsProtected(string? path, SignatureInfo? signature, out string reason) =>
        IsProtected(path, DefaultFolders(), signature, out reason);

    public static bool IsProtected(string? path, IEnumerable<string> protectedFolders, SignatureInfo? signature, out string reason)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            reason = "The program's file path is unknown. Run SpectraNetworkManager as Administrator so Windows reveals it.";
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

    /// <summary>
    /// Checks whether an executable cannot be subjected to 5-Stage Active Defense Quarantine / IFEO Execution Lockout.
    /// Shared runtime components like WebView2 and Ollama are strictly protected from execution lockout because
    /// killing their ability to launch breaks local browser profile caches and local AI inference engines system-wide.
    /// </summary>
    public static bool IsExecutionLockoutProtected(string? path, out string reason)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            reason = "Executable path is empty.";
            return true;
        }

        string fileName = System.IO.Path.GetFileName(path);
        if (DisallowedExecutionLockoutBinaries.Contains(fileName))
        {
            reason = $"'{fileName}' is a critical shared runtime or system component (e.g. WebView2 cache engine, Ollama local server). Full execution lockout (IFEO) is disabled because it breaks local application profile creation, GPU caches, and dependent services across Windows. If you wish to restrict network access, use a Firewall rule instead.";
            return true;
        }

        if (IsProtected(path, null, out string osReason))
        {
            reason = osReason;
            return true;
        }

        reason = "";
        return false;
    }
}
