namespace SpectraNetworkManager.Core.Ai;

public static class DeterministicAnalysisEngine
{
    public static InvestigationReport Analyze(
        VerifiedProcessEvidence evidence,
        string language = "English",
        bool isFallback = false)
    {
        bool isDutch = language.Equals("Nederlands", StringComparison.OrdinalIgnoreCase) ||
                       language.Equals("nl", StringComparison.OrdinalIgnoreCase);

        var findings = new List<string>();
        var capabilities = new List<string>();
        var uncertainties = new List<string>();

        int riskScore = 30;
        ThreatVerdict verdict = ThreatVerdict.LowRisk;
        RecommendedAction recommendation = RecommendedAction.Monitor;

        // Capabilities extraction
        if (evidence.ListeningPorts.Count > 0)
        {
            capabilities.Add(isDutch ? "Netwerkserver / Luisterend" : "Network Listener / Server");
            findings.Add(isDutch
                ? $"Luistert op {evidence.ListeningPorts.Count} lokale poort(en): {string.Join(", ", evidence.ListeningPorts)}"
                : $"Listening on {evidence.ListeningPorts.Count} local port(s): {string.Join(", ", evidence.ListeningPorts)}");
        }

        if (evidence.ActiveConnections.Count > 0)
        {
            capabilities.Add(isDutch ? "Netwerkclient" : "Network Client");
            findings.Add(isDutch
                ? $"Heeft {evidence.ActiveConnections.Count} actieve netwerkverbinding(en)."
                : $"Has {evidence.ActiveConnections.Count} active network socket(s).");
        }

        if (evidence.Services.Count > 0)
        {
            capabilities.Add(isDutch ? "Windows Service" : "Windows Service Host");
            findings.Add(isDutch
                ? $"Gekoppeld aan geregistreerde Windows-service(s): {string.Join(", ", evidence.Services)}"
                : $"Attributed to registered Windows service(s): {string.Join(", ", evidence.Services)}");
        }

        if (evidence.StartupEntries.Count > 0)
        {
            capabilities.Add(isDutch ? "Automatisch Opstarten (Persistentie)" : "Auto-Start Persistence");
            findings.Add(isDutch
                ? $"Geregistreerd voor automatisch opstarten: {string.Join(", ", evidence.StartupEntries)}"
                : $"Configured for automatic system startup: {string.Join(", ", evidence.StartupEntries)}");
        }

        // Location & Path analysis
        string path = evidence.ExecutablePath ?? "";
        bool inSystem32 = path.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase) ||
                          path.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase);
        bool inProgramFiles = path.Contains(@"\Program Files\", StringComparison.OrdinalIgnoreCase) ||
                              path.Contains(@"\Program Files (x86)\", StringComparison.OrdinalIgnoreCase);
        bool inTemp = path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                      path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase);
        bool inDownloads = path.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase);

        // Masquerade check
        string nameLower = evidence.ProcessName.ToLowerInvariant();
        bool isKnownSystemName = nameLower is "svchost.exe" or "explorer.exe" or "csrss.exe" or "lsass.exe" or "services.exe";
        bool isMasquerading = isKnownSystemName && !inSystem32 && !path.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase);

        if (isMasquerading)
        {
            riskScore = 95;
            verdict = ThreatVerdict.Malicious;
            recommendation = RecommendedAction.Quarantine;
            findings.Add(isDutch
                ? $"🚨 ERNSTIGE DREIGING: Procesnaam '{evidence.ProcessName}' bootst een Windows systeembestand na buiten System32!"
                : $"🚨 CRITICAL THREAT: Process name '{evidence.ProcessName}' masquerades as a Windows core binary outside System32!");
        }
        else if (evidence.VerificationLevel == IdentityVerificationLevel.TamperedOrUntrusted)
        {
            riskScore = 90;
            verdict = ThreatVerdict.Malicious;
            recommendation = RecommendedAction.Quarantine;
            findings.Add(isDutch
                ? "🚨 Bestandshandtekening is gemanipuleerd of ongeldig (mogelijk geïnfecteerd)."
                : "🚨 Digital signature is tampered or invalid (possible file modification or infection).");
        }
        else if (inTemp || inDownloads || evidence.VerificationLevel == IdentityVerificationLevel.SuspiciousLocation)
        {
            riskScore = 70;
            verdict = ThreatVerdict.Suspicious;
            recommendation = RecommendedAction.BlockFirewall;
            findings.Add(isDutch
                ? $"⚠️ Proces voert uit vanuit een onveilige map: {path}"
                : $"⚠️ Process executes from a high-risk directory: {path}");
            uncertainties.Add(isDutch
                ? "Tijdelijke mappen worden vaak gebruikt door downloaders en malware droppers."
                : "Temporary directories are frequently utilized by unverified downloaders and droppers.");
        }
        else if (evidence.VerificationLevel == IdentityVerificationLevel.VerifiedSystemBinary)
        {
            riskScore = 5;
            verdict = ThreatVerdict.Safe;
            recommendation = RecommendedAction.Allow;
            findings.Add(isDutch
                ? $"🛡️ Geverifieerd Microsoft Windows systeemonderdeel ({evidence.Publisher ?? "Microsoft Windows"})."
                : $"🛡️ Verified Microsoft Windows operating system binary ({evidence.Publisher ?? "Microsoft Windows"}).");
        }
        else if (evidence.VerificationLevel == IdentityVerificationLevel.VerifiedPublisherBinary)
        {
            riskScore = 15;
            verdict = ThreatVerdict.Safe;
            recommendation = RecommendedAction.Allow;
            findings.Add(isDutch
                ? $"✔ Geldige digitale handtekening van vertrouwde uitgever: {evidence.Publisher}."
                : $"✔ Valid Authenticode digital signature by trusted publisher: {evidence.Publisher}.");
        }
        else if (evidence.VerificationLevel == IdentityVerificationLevel.UnsignedOrUnverified)
        {
            if (inProgramFiles)
            {
                riskScore = 35;
                verdict = ThreatVerdict.LowRisk;
                recommendation = RecommendedAction.Monitor;
                findings.Add(isDutch
                    ? "Bestand bevindt zich in Program Files maar heeft geen digitale handtekening."
                    : "Executable resides in Program Files directory but lacks an Authenticode signature.");
            }
            else
            {
                riskScore = 55;
                verdict = ThreatVerdict.Suspicious;
                recommendation = RecommendedAction.Monitor;
                findings.Add(isDutch
                    ? "Onbekend niet-ondertekend programma dat netwerkactiviteit vertoont."
                    : "Unsigned binary exhibiting network activity from non-standard location.");
            }
            uncertainties.Add(isDutch
                ? "Zonder digitale handtekening kan de herkomst van de maker niet wiskundig worden gegarandeerd."
                : "Without a cryptographic signature, publisher origin cannot be mathematically verified.");
        }
        else
        {
            riskScore = 50;
            verdict = ThreatVerdict.Unknown;
            recommendation = RecommendedAction.Monitor;
            uncertainties.Add(isDutch
                ? "Proces was beëindigd of niet toegankelijk vóór volledige deterministische verificatie."
                : "Process terminated or was inaccessible before full deterministic inspection completed.");
        }

        // Summary phrasing
        string summary;
        if (isDutch)
        {
            summary = verdict switch
            {
                ThreatVerdict.Safe => $"Het proces '{evidence.ProcessName}' is geverifieerd als legitiem en veilig.",
                ThreatVerdict.LowRisk => $"Het proces '{evidence.ProcessName}' vertoont standaard gedrag met laag risico.",
                ThreatVerdict.Suspicious => $"Het proces '{evidence.ProcessName}' vereist aandacht wegens onveilige kenmerken of niet-ondertekende status.",
                ThreatVerdict.Malicious => $"WAARSCHUWING: '{evidence.ProcessName}' vertoont duidelijke indicatoren van manipulatie of masquerading!",
                _ => $"Onvoldoende runtime-gegevens om de betrouwbaarheid van '{evidence.ProcessName}' definitief vast te stellen."
            };
        }
        else
        {
            summary = verdict switch
            {
                ThreatVerdict.Safe => $"Process '{evidence.ProcessName}' is cryptographically verified and safe.",
                ThreatVerdict.LowRisk => $"Process '{evidence.ProcessName}' appears to be standard application software with low risk profile.",
                ThreatVerdict.Suspicious => $"Process '{evidence.ProcessName}' warrants caution due to unverified origin or execution path.",
                ThreatVerdict.Malicious => $"CRITICAL WARNING: Process '{evidence.ProcessName}' exhibits strong indicators of tampering or masquerading!",
                _ => $"Insufficient runtime telemetry to establish definite origin for '{evidence.ProcessName}'."
            };
        }

        string modelEngine = isFallback
            ? (isDutch ? "Deterministische Engine (Fallback)" : "Deterministic Engine (Fallback)")
            : (isDutch ? "Deterministische Engine (Offline)" : "Deterministic Engine (Offline)");

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
            KeyFindings = findings,
            IdentifiedCapabilities = capabilities,
            Uncertainties = uncertainties,
            Recommendation = recommendation,
            IsAiGenerated = false,
            ModelUsed = modelEngine,
            Evidence = evidence
        };
    }
}
