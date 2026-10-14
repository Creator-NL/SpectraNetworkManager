# NetSentinel Security Architecture & Policy

**Project:** NetSentinel  
**Maintainer:** Biohazard Corp / Creator-NL  
**Repository:** https://github.com/Creator-NL/NetSentinel  

---

## 1. Security Philosophy

Because NetSentinel inspects low-level networking data, manages Windows Firewall rules, and interacts with system-level network configurations, the application itself is built as a high-security target:

1. **Least Privilege Architecture:** The GUI front-end runs in user context; privileged actions (firewall manipulation, DNS binding on port 53) are handled through the Windows Service (`NetSentinel.Engine`) or when explicitly run elevated.
2. **Access-Controlled IPC:** Named Pipe communication between GUI clients and the background engine is protected by Windows Security Descriptors, restricted exclusively to `LocalSystem` and the `Builtin\Administrators` group.
3. **No Unsafe Interprocess Execution:** Antivirus-flagged techniques (such as running base64-encoded PowerShell scripts to inspect certificates) have been completely removed. All signature checking is performed via native Windows APIs (`WinVerifyTrust`, `CryptCATAdmin*`).
4. **Resilience to Hostile Input:** The DNS sinkhole parser, wire decoding, and event logs are strictly bounds-checked and fuzz-tested with randomized inputs to ensure buffer overflow and crash resistance.
5. **Fail-Safe Rollback Mechanisms:** Any configuration changes to Strict Mode or System DNS require explicit user confirmation within 60 seconds; failure to confirm automatically rolls back the system to standard Windows defaults.

---

## 2. Threat Model & Mitigations

| Threat | Potential Impact | NetSentinel Mitigation |
| :--- | :--- | :--- |
| **Tampered / Malicious Binary** | Unauthorized network exfiltration | Native Authenticode verification checks both embedded signatures and Windows catalog signatures (`CryptCATAdmin`). |
| **Malicious IPC Client** | Unauthorized firewall or DNS manipulation | The Named Pipe server enforces strict Access Control Lists (ACLs); non-administrator unprivileged processes cannot send commands to the engine. |
| **Malformed DNS Packets** | Denial of service / Remote code execution | The DNS server enforces compression pointer jump limits (max 64), validates EDNS OPT structures, and handles memory safely in managed C# with strict bounds checks. |
| **Accidental Network Lockout** | Loss of network connectivity | Automatic 60-second rollback on Strict Mode and DNS switches; `--safe` recovery mode; instant PANIC button. |
| **Antivirus False Positives** | Tool blocking / quarantine | All binaries are built cleanly with standard Microsoft .NET SDK, signed where possible, and avoid script injection or heuristic triggers. |

---

## 3. Reporting a Security Vulnerability

We welcome security researchers and community members reporting security vulnerabilities.

### Responsible Disclosure Guidelines
* **Do NOT report security vulnerabilities via public GitHub issues.**
* Please submit security advisories privately via **GitHub Security Advisories** on the repository:  
  `https://github.com/Creator-NL/NetSentinel/security/advisories`
* Alternatively, contact the maintainer directly through the GitHub profile (`Creator-NL`).

### Our Commitment
* We will acknowledge receipt of your vulnerability report within **48 hours**.
* We will provide an initial assessment and estimated fix timeline within **5 business days**.
* Once the vulnerability is remediated, a security release will be published and proper credit given to the reporter (unless anonymity is requested).
