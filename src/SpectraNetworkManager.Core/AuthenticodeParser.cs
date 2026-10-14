using System.Text.Json;

namespace SpectraNetworkManager.Core;

/// <summary>Turns the JSON printed by our PowerShell signature check into <see cref="SignatureInfo"/> values.</summary>
public static class AuthenticodeParser
{
    /// <param name="json">Array of { I, Status, Subject, IsOs } where I is the index into <paramref name="paths"/>.</param>
    public static IReadOnlyDictionary<string, SignatureInfo> Parse(string json, IReadOnlyList<string> paths)
    {
        var result = new Dictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase);
        json = json.Trim().TrimStart('\uFEFF');
        if (json.Length == 0) return result;

        using var doc = JsonDocument.Parse(json);
        var items = doc.RootElement.ValueKind == JsonValueKind.Array
            ? doc.RootElement.EnumerateArray().ToList()
            : new List<JsonElement> { doc.RootElement };

        foreach (var item in items)
        {
            if (!item.TryGetProperty("I", out var iProp) || !iProp.TryGetInt32(out int index)) continue;
            if (index < 0 || index >= paths.Count) continue;

            string status = item.TryGetProperty("Status", out var st) ? st.GetString() ?? "" : "";
            string subject = item.TryGetProperty("Subject", out var su) ? su.GetString() ?? "" : "";
            bool isOs = item.TryGetProperty("IsOs", out var os) && os.ValueKind == JsonValueKind.True;

            result[paths[index]] = new SignatureInfo(MapStatus(status), CommonName(subject), isOs, status);
        }
        return result;
    }

    public static SignatureStatus MapStatus(string powerShellStatus) => powerShellStatus switch
    {
        "Valid" => SignatureStatus.Valid,
        "NotSigned" => SignatureStatus.NotSigned,
        "NotTrusted" => SignatureStatus.Untrusted,
        "HashMismatch" => SignatureStatus.Tampered,
        _ => SignatureStatus.Unknown,     // UnknownError, NotSupportedFileFormat, Incompatible, ...
    };

    /// <summary>Extracts CN (or, failing that, O) from a certificate subject like: CN="Foo, Inc.", O=Foo, C=US</summary>
    public static string? CommonName(string subject)
    {
        return Field(subject, "CN") ?? Field(subject, "O");
    }

    private static string? Field(string subject, string key)
    {
        int i = 0;
        while (i < subject.Length)
        {
            while (i < subject.Length && (subject[i] == ' ' || subject[i] == ',')) i++;
            int eq = subject.IndexOf('=', i);
            if (eq < 0) return null;

            string name = subject[i..eq].Trim();
            int v = eq + 1;
            string value;

            if (v < subject.Length && subject[v] == '"')
            {
                int end = v + 1;
                var sb = new System.Text.StringBuilder();
                while (end < subject.Length)
                {
                    if (subject[end] == '"')
                    {
                        if (end + 1 < subject.Length && subject[end + 1] == '"') { sb.Append('"'); end += 2; continue; }
                        break;
                    }
                    sb.Append(subject[end++]);
                }
                value = sb.ToString();
                i = Math.Min(end + 1, subject.Length);
            }
            else
            {
                int end = subject.IndexOf(',', v);
                if (end < 0) end = subject.Length;
                value = subject[v..end].Trim();
                i = end;
            }

            if (name.Equals(key, StringComparison.OrdinalIgnoreCase) && value.Length > 0) return value;
        }
        return null;
    }
}
