using System.Text.Json;

namespace SpectraNetworkManager.Core.Ai;

public static class InvestigationValidator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static InvestigationReport ValidateAndNormalize(
        string rawLlmResponse,
        VerifiedProcessEvidence evidence,
        string modelName,
        string language = "English")
    {
        bool isDutch = language.Equals("Nederlands", StringComparison.OrdinalIgnoreCase) ||
                       language.Equals("nl", StringComparison.OrdinalIgnoreCase);

        ThreatVerdict verdict = ThreatVerdict.Unknown;
        int riskScore = 50;
        string summary = "";
        var keyFindings = new List<string>();
        var capabilities = new List<string>();
        var uncertainties = new List<string>();
        RecommendedAction recommendation = RecommendedAction.Monitor;

        bool parsedSuccessfully = false;

        try
        {
            string cleanedJson = ExtractJsonBlock(rawLlmResponse);
            using var doc = JsonDocument.Parse(cleanedJson);
            var root = doc.RootElement;

            if (root.TryGetProperty("verdict", out var vProp))
            {
                if (Enum.TryParse<ThreatVerdict>(vProp.GetString(), ignoreCase: true, out var v))
                    verdict = v;
            }

            if (root.TryGetProperty("risk_score", out var rProp) && rProp.TryGetInt32(out int r))
            {
                riskScore = Math.Clamp(r, 0, 100);
            }

            if (root.TryGetProperty("executive_summary", out var sProp))
            {
                summary = PromptSanitizer.Sanitize(sProp.GetString(), 400);
            }

            if (root.TryGetProperty("key_findings", out var kProp) && kProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in kProp.EnumerateArray())
                {
                    string f = PromptSanitizer.Sanitize(item.GetString(), 200);
                    if (!string.IsNullOrEmpty(f)) keyFindings.Add(f);
                }
            }

            if (root.TryGetProperty("identified_capabilities", out var cProp) && cProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in cProp.EnumerateArray())
                {
                    string c = PromptSanitizer.Sanitize(item.GetString(), 100);
                    if (!string.IsNullOrEmpty(c)) capabilities.Add(c);
                }
            }

            if (root.TryGetProperty("uncertainties", out var uProp) && uProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in uProp.EnumerateArray())
                {
                    string u = PromptSanitizer.Sanitize(item.GetString(), 200);
                    if (!string.IsNullOrEmpty(u)) uncertainties.Add(u);
                }
            }

            if (root.TryGetProperty("recommendation", out var recProp))
            {
                if (Enum.TryParse<RecommendedAction>(recProp.GetString(), ignoreCase: true, out var rec))
                    recommendation = rec;
            }

            parsedSuccessfully = true;
        }
        catch
        {
            // Fall back if LLM JSON format was malformed
            parsedSuccessfully = false;
        }

        if (!parsedSuccessfully || string.IsNullOrWhiteSpace(summary))
        {
            // Generate fallback deterministic report
            return DeterministicAnalysisEngine.Analyze(evidence, language, isFallback: true);
        }

        // --- C# DETERMINISTIC SECURITY ENFORCEMENT ---

        // Rule 1: An unsigned or tampered binary can NEVER be marked as unconditionally safe
        if (evidence.VerificationLevel is IdentityVerificationLevel.UnsignedOrUnverified or
            IdentityVerificationLevel.TamperedOrUntrusted or
            IdentityVerificationLevel.SuspiciousLocation)
        {
            if (verdict == ThreatVerdict.Safe && riskScore < 20)
            {
                verdict = ThreatVerdict.LowRisk;
                riskScore = Math.Max(riskScore, 25);
            }

            string signatureWarning = isDutch
                ? "Cryptografische zekerheid ontbreekt: bestand heeft geen geverifieerde Authenticode-handtekening van een vertrouwde root."
                : "Cryptographic proof missing: executable lacks a valid Authenticode signature from a trusted root.";

            if (!uncertainties.Any(u => u.Contains("signature", StringComparison.OrdinalIgnoreCase) ||
                                       u.Contains("handtekening", StringComparison.OrdinalIgnoreCase)))
            {
                uncertainties.Insert(0, signatureWarning);
            }
        }

        // Rule 2: Suspicious location checks
        if (evidence.VerificationLevel == IdentityVerificationLevel.SuspiciousLocation)
        {
            if (verdict is ThreatVerdict.Safe or ThreatVerdict.LowRisk)
            {
                verdict = ThreatVerdict.Suspicious;
                riskScore = Math.Max(riskScore, 65);
                recommendation = RecommendedAction.BlockFirewall;
            }

            string locWarning = isDutch
                ? "Verdachte uitvoerlocatie: bestand draait vanuit een tijdelijke of downloadmap."
                : "Suspicious execution location: binary runs from a temporary or downloads directory.";

            if (!uncertainties.Any(u => u.Contains("location", StringComparison.OrdinalIgnoreCase) ||
                                       u.Contains("locatie", StringComparison.OrdinalIgnoreCase)))
            {
                uncertainties.Insert(0, locWarning);
            }
        }

        // Rule 3: Truncated command lines or ephemeral process uncertainty
        if (string.IsNullOrWhiteSpace(evidence.CommandLine) &&
            !uncertainties.Any(u => u.Contains("command", StringComparison.OrdinalIgnoreCase) ||
                                   u.Contains("opdrachtregel", StringComparison.OrdinalIgnoreCase)))
        {
            uncertainties.Add(isDutch
                ? "Volledige opdrachtregelparameters waren niet toegankelijk tijdens inspectie."
                : "Full command-line arguments were not accessible during inspection.");
        }

        return new InvestigationReport
        {
            Id = Guid.NewGuid().ToString("N"),
            Timestamp = DateTimeOffset.UtcNow,
            TargetType = "Process",
            TargetIdentifier = evidence.ExecutablePath ?? evidence.ProcessName,
            Pid = evidence.Pid,
            ProcessName = evidence.ProcessName,
            VerificationLevel = evidence.VerificationLevel,
            Verdict = verdict,
            RiskScore = riskScore,
            ExecutiveSummary = summary,
            KeyFindings = keyFindings,
            IdentifiedCapabilities = capabilities,
            Uncertainties = uncertainties,
            Recommendation = recommendation,
            IsAiGenerated = true,
            ModelUsed = modelName,
            Evidence = evidence
        };
    }

    private static string ExtractJsonBlock(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "{}";

        string trimmed = raw.Trim();
        // Look for ```json ... ``` or ``` ... ```
        int startFence = trimmed.IndexOf("```", StringComparison.Ordinal);
        if (startFence >= 0)
        {
            int startLine = trimmed.IndexOf('\n', startFence);
            if (startLine > startFence)
            {
                int endFence = trimmed.IndexOf("```", startLine, StringComparison.Ordinal);
                if (endFence > startLine)
                {
                    return trimmed[startLine..endFence].Trim();
                }
            }
        }

        // Look for first '{' and last '}'
        int firstBrace = trimmed.IndexOf('{');
        int lastBrace = trimmed.LastIndexOf('}');
        if (firstBrace >= 0 && lastBrace > firstBrace)
        {
            return trimmed.Substring(firstBrace, lastBrace - firstBrace + 1);
        }

        return trimmed;
    }
}
