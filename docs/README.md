# SpectraNetworkManager v2.0.0

[![Release](https://img.shields.io/badge/Release-v2.0.0-00E676?style=flat-square&logo=github)](https://github.com/Creator-NL/SpectraNetworkManager/releases)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20(x64)-00D4FF?style=flat-square&logo=windows)](https://github.com/Creator-NL/SpectraNetworkManager)
[![Framework](https://img.shields.io/badge/.NET-8.0%20(Self--Contained)-7928CA?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-F5A623?style=flat-square)](../LICENSE)
[![Zero Telemetry](https://img.shields.io/badge/Privacy-100%25%20Local%20%7C%20Zero%20Telemetry-22E8FF?style=flat-square)](PRIVACY.md)

**SpectraNetworkManager** is an elite, open-source Windows network security platform combining **real-time socket monitoring**, **per-application outbound firewall control**, an **in-memory DNS sinkhole (Pi-hole style)**, a **5-stage active defense quarantine vault**, a **zero-driver packet inspector**, a **browser-level declarative guard (Manifest V3)**, and a **local AI threat intelligence engine with interactive chat (`💬 Ask Spectra AI`)**.

> [!TIP]
> **Try the Interactive Online Demo:** Test core functions right in your browser before downloading or installing!  
> 🌐 **[https://biohazard-corp.nl/spectranetworkmanager.html](https://biohazard-corp.nl/spectranetworkmanager.html)**  
> 🏠 Official Hub: **[https://biohazard-corp.nl](https://biohazard-corp.nl)**

---

## 🌐 Live Interactive Demo & Official Website

You can test SpectraNetworkManager directly in your browser without installing anything:
- 🔗 **Interactive Web Demo & Simulator**: [https://biohazard-corp.nl/spectranetworkmanager.html](https://biohazard-corp.nl/spectranetworkmanager.html)
  - **Live Connection Monitor**: Experience real-time connection inspection and test Allow / Block actions.
  - **Interactive Rule Builder**: Experiment with protocol, port, and address filter rule generation.
  - **DNS Sinkhole Simulator**: Test domain blocking, wildcard rules, and CNAME cloaking defenses.
  - **Strict Mode Simulation**: Experience the 60-second safety rollback countdown mechanism.
- 🏠 **Official Website**: [https://biohazard-corp.nl](https://biohazard-corp.nl) — explore more software, updates, and community projects.

---

## 🚀 What's New in Version 2.0.0

Version 2.0.0 represents a massive evolution into a complete, enterprise-grade personal cybersecurity center:

* **💬 Spectra AI Threat Intelligence & Chat**: Dual-engine forensics powered by local **Ollama** LLMs (with smart offline deterministic fallback). Inspects any binary, calculates a **0–100 Risk Score**, surfaces Authenticode signatures, and includes an interactive **`💬 Ask Spectra AI`** chat thread with quick prompt chips (`🛡️ Is this safe?`, `🌐 Why network access?`, `🚫 Safe to block?`, `🔍 Explain publisher`).
* **🛡️ 5-Stage Active Defense Quarantine Vault**: Complete containment of suspicious or hostile executables across 5 defense rings: (1) Process & socket kill, (2) Image File Execution Options (IFEO) debugger lockout, (3) Windows Service termination, (4) Auto-start removal, and (5) Kernel WFP socket blocking — with 1-click safe reversible restore and automatic self-healing.
* **🌐 Spectra Browser Guard (Manifest V3 Extension + Native Messaging Host)**: Zero-latency in-browser declarative request blocking for Chrome, Edge, and Firefox. Blocks YouTube pre-roll/mid-roll ads, tracking beacons, and telemetry; includes an optional YouTube Shorts toggle and an in-browser visual element picker.
* **📺 Smart TV & Mobile LAN Protection Hub**: Pair phones and smart TVs via an instant on-screen QR code; includes a local companion dashboard, a 3-in-1 Smart Proxy / L3 Gateway Router with TLS SNI inspection, and separate Phone & TV domain blocking rules.
* **🚀 Startup & Auto-Start Intelligence Manager**: Deep enumeration of Registry Run/RunOnce, Startup folders, Task Scheduler tasks, and Store/MSIX StartupTasks. Features dynamic red/green firewall status coloring (`Blocked` in red, `Allowed` in green) and 1-click 5-stage quarantine.
* **📋 Rules & Firewall Blocks Forensic Split Views**: Side-by-side diagnostic inspector drawers with deep caller attribution, SHA-256 hash tracking, and one-click firewall actions.
* **🔍 Zero-Driver Packet Inspector**: High-speed promiscuous and raw socket capture with built-in dissectors for HTTP, TLS SNI, DNS, QUIC, ARP, and ICMP, plus hex stream inspection and Wireshark PCAPNG export.
* **🌍 Multi-Language Localization**: Instant runtime switching between **English**, **Nederlands (Dutch)**, and **Auto (System Culture)**.
* **⚡ Single-Instance Resilience**: Mutex-guarded single instance management with cross-elevation named pipe IPC and window activation.

---

## 🧭 Comprehensive Feature Tour (14 Dedicated Tabs)

### 1. 🔌 Connections (Live Socket Activity)
- Inspects every established, listening, and closing TCP and UDP socket in real time.
- Maps connections directly to process name, PID, executable icon, full disk path, and Authenticode signature status.
- Shows live upload and download speeds per process.
- Resolves remote IP hostnames via background reverse DNS and looks up Country / Autonomous System Number (ASN) metadata.
- Context menu actions: Allow, Block in Firewall, 5-Stage Quarantine, Investigate with Spectra AI, Open File Location, and End Process.

### 2. 📦 Programs (Application Catalog & Policy)
- Comprehensive view of every program that has ever communicated on your network.
- Visual badge indicators for verified publishers (`✔ Publisher`), system components (`(Windows)`), untrusted signatures (`✘ untrusted`), and unsigned binaries (`not signed`).
- Tracks total lifetime bytes sent and received.
- Distinguishes newly discovered programs (**NEW** in magenta) awaiting a decision.

### 3. 🚀 Startup (Auto-Start Intelligence)
- Enumerate auto-start entries across all Windows persistence points:
  - Windows Registry (`HKLM`, `HKCU`, and 32-bit `WOW6432Node` Run / RunOnce)
  - User and Common Startup folders
  - Windows Task Scheduler (Active logon and scheduled triggers)
  - Windows Store / MSIX packaged `StartupTask` contracts (e.g. ChatGPT, Claude, Spotify, Windows Terminal)
  - 3rd-Party Auto-Start Services
- 1:1 synchronization with Windows Task Manager `StartupApproved` registry keys.
- **Dynamic Firewall Status**: Blocked items turn **Bold Red**, Allowed items turn **Bold Green**, and unconfigured entries remain muted.
- Immediate 1-click `[ 🛡️ 5-Stage Quarantine... ]` containment for suspicious startup programs.

### 4. 📈 Traffic & Top Talkers
- Visual bandwidth consumption graphs and top bandwidth-consuming processes.
- Protocol distribution breakdown (TCP, UDP, DNS, HTTPS).
- Persistent SQLite traffic history tracking hourly and daily bandwidth trends.

### 5. 📡 Port Scanner & LAN Device Discovery
- High-speed multithreaded LAN subnet sweep.
- Identifies active IP addresses, MAC addresses, NIC vendors, hostnames, and open TCP/UDP ports.
- Special detection and tagging for Smart TVs (Samsung, LG webOS, Android TV), game consoles, and IoT devices.

### 6. 🔬 Packets (Zero-Driver Packet Inspector)
- Capture live packets directly without installing WinPcap or Npcap drivers.
- Correlates captured packets directly to the originating local process.
- **Protocol Dissectors**: Automatically parses HTTP requests/responses, TLS Client Hello (Server Name Indication / SNI), DNS queries and answers, QUIC handshakes, ARP announcements, and ICMP messages.
- Real-time Hex and ASCII stream inspector.
- **PCAPNG Export**: Export selected packets or the full capture to standard `.pcapng` format for deep analysis in Wireshark.

### 7. 📺 TV & Mobile (LAN Protection Hub)
- Network-wide protection for smartphones, tablets, smart TVs, and IoT appliances.
- **QR-Code Mobile Dashboard**: Scan an on-screen QR code to open the lightweight local web companion on your phone.
- **3-in-1 Network Hub**:
  - Smart HTTP/HTTPS Proxy (Port 8888 with WPAD auto-discovery support)
  - L3 Gateway Router with transparent TLS SNI extraction
  - Built-In DHCP Server for automated client configuration
- **Independent Rules**: Block telemetry or ads specifically on Smart TVs and phones without affecting PC browsing rules (`tv-mobile-rules.json`).

### 8. 🛡️ Browser Guard (Manifest V3 Extension)
- Native companion extension for **Google Chrome**, **Microsoft Edge**, and **Mozilla Firefox**.
- Powered by a local Native Messaging Host (`SpectraNetworkManager.BrowserHost.exe`).
- Zero-latency declarative blocking via Manifest V3 `declarativeNetRequest`.
- Pre-built shields for YouTube ads, video trackers, promo cards, and annotation popups.
- **YouTube Shorts Switch**: Optional toggle to suppress distracting YouTube Shorts feeds (defaults to off/unblocked).
- **Element Picker DOM Shield**: Right-click any annoying web element in your browser to permanently block it with 1 click.

### 9. 🧠 Spectra AI (Threat Intelligence & Chat Assistant)
- Deep forensic inspection of executables, network telemetry, and suspicious behavior.
- **Evidence-Based Security Engine**:
  - Authenticode digital signature verification
  - Windows System directory validation (`System32`, `SysWOW64`)
  - Executable SHA-256 hash calculation and VirusTotal correlation
  - Telemetry capability extraction (listening ports, remote endpoints, DNS queries)
- **0–100 Risk Score & Verdicts**: Automatically categorizes targets as `🟢 SAFE`, `🔵 LOW RISK`, `🟡 SUSPICIOUS`, or `🔴 MALICIOUS`.
- **Local Ollama Integration**: Connects to your local Ollama instance (defaulting to `127.0.0.1:11434` with models like `llama3`, `mistral`, or `phi3`) for private neural reasoning.
- **Deterministic Offline Fallback**: Fully functional even when Ollama is offline or not installed.
- **💬 Interactive Chat (`Ask Spectra AI`)**:
  - Sub-tab switcher to toggle between interactive chat and past investigation records.
  - Contextual awareness of the currently selected target.
  - Quick prompt suggestions: `🛡️ Is this safe?`, `🌐 Why network access?`, `🚫 Safe to block?`, and `🔍 Explain publisher`.

### 10. 📋 Rules (Firewall Policy Manager)
- Centralized manager for all persistent application firewall rules.
- Side-by-side details inspector displaying executable metadata, disk footprint, SHA-256 hash, and active firewall state.
- Supports granular rule specifications:
  - Direction: Incoming, Outgoing, or Both.
  - Protocol: TCP, UDP, or Any.
  - Port Filtering: Single ports, comma-separated lists, and port ranges (e.g. `80,443,8000-8100`).
  - IP Address Filtering: Single IPs, subnets (`10.0.0.0/8`), CIDR blocks, or IP ranges in both IPv4 and IPv6.
- Automatically verifies that created rules exist in Windows Firewall (`active`, `PARTIAL`, `MISSING`).

### 11. ☣️ Quarantine (5-Stage Active Defense Vault)
- Military-grade isolation for untrusted, tampered, or hostile software:
  1. **Process & Socket Kill**: Forcefully terminates all running process instances and severs active TCP connections.
  2. **Execution Lockout (IFEO)**: Registers an Image File Execution Options debugger redirect preventing the binary from spawning again.
  3. **Service Disabling**: Detects and stops any Windows Services hosted by the executable and sets their startup type to `Disabled`.
  4. **Auto-Start Removal**: Disables matching entries in the Registry, Startup folder, and Task Scheduler.
  5. **Firewall Drop**: Adds inbound and outbound Windows Firewall block rules.
- **Safe Reversible Restore**: 1-click restoration reverses all 5 layers, restoring the program to normal operation.
- **Self-Healing Reconciliation**: Automatically detects and heals orphaned lockouts or attempts to lock protected system components (WebView2, Ollama, Windows components).

### 12. 🔒 Strict Mode ("Block Outbound by Default")
- Switches Windows Firewall's outbound default policy to BLOCK on all network profiles.
- Only programs with an explicit Allow rule or trusted publisher signature can communicate.
- **60-Second Safety Rollback**: Requires user confirmation and automatic connectivity testing; if unconfirmed or connectivity drops, strict mode automatically reverts within 60 seconds.

### 13. 🛡️ DNS Sinkhole (Ad & Tracker Blocker)
- Local high-speed multithreaded DNS server preloaded with 83,000+ ad and tracking domains.
- Pre-parsed in-memory cache ready in milliseconds on boot.
- **1-Click System DNS Switch**: Reconfigures selected network adapters to `127.0.0.1` / `::1` with automatic backup and 60-second safety rollback.
- Supports encrypted upstreams via **DNS-over-HTTPS (DoH)** and **DNS-over-TLS (DoT)** with health checking and automatic failover.
- Persistent SQLite query logging (`dns-history.db`) with CSV export, domain classification, and privacy IP masking.
- Firefox canary protection (`use-application-dns.net`) preventing browser DoH bypass.

### 14. 🚫 Firewall Blocks (Diagnostic WFP Event Monitor)
- Real-time monitor listening to Windows Filtering Platform (WFP) drop events.
- Side-by-side forensic drawer detailing event timestamps, source and destination ports, protocols, and smart caller identification.
- Filters out kernel loopback and noise events to highlight real application blocks.
- 1-click buttons to immediately allow the blocked executable or launch a Spectra AI investigation.

---

## 🛑 Emergency Recovery & Safety Mechanisms

SpectraNetworkManager is built with zero-lockout safety principles:

1. **PANIC Emergency Reset Button**: Available on the top bar and in the system tray menu. Instantly restores Windows Firewall outbound policy to Allow, deletes all SpectraNetworkManager firewall rules, and restores original adapter DNS configurations.
2. **Safe Recovery Mode (`--safe`)**: Run `SpectraNetworkManager.exe --safe` (or click "SpectraNetworkManager (Safe Recovery Mode)" in the Start Menu) to immediately reset all firewall and DNS configurations offline without opening the UI.
3. **Manual Command Prompt Recovery**:
   ```cmd
   netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
   ```
4. **Emergency IFEO Cleaner Script**: Located at [`scripts/Unlock-QuarantineLockouts.ps1`](../scripts/Unlock-QuarantineLockouts.ps1) to clear any orphaned execution debugger lockouts.

---

## 📦 Installation & System Requirements

### Requirements
- **OS**: Windows 10 (version 1809 or higher) or Windows 11 (64-bit x64).
- **Privileges**: Administrator rights (required for Windows Filtering Platform, firewall rules, and network adapter settings).
- **Runtime**: Self-contained (no external .NET installation required).

### Installation Methods
1. **Production Installer**:
   Download and run `SpectraNetworkManager-v2.0.0-Setup.exe`. Follow the guided wizard.
2. **Portable Package**:
   Download `SpectraNetworkManager-v2.0.0-Portable.zip`, extract to any folder, and run `SpectraNetworkManager.exe` as Administrator.

### Automated Package Build
To compile and package the installer and portable ZIP locally:
```powershell
powershell -ExecutionPolicy Bypass -File build-package.ps1 -SkipTests
```
The output artifacts are written directly to `installer\output\`:
- `SpectraNetworkManager-v2.0.0-Setup.exe`
- `SpectraNetworkManager-v2.0.0-Portable.zip`

---

## 💻 Building from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/Creator-NL/SpectraNetworkManager.git
   cd SpectraNetworkManager
   ```
2. Open `SpectraNetworkManager.sln` in **Visual Studio 2022** (v17.8 or newer with *.NET desktop development* workload).
3. Ensure **`SpectraNetworkManager.App`** is set as the startup project.
4. Or build via the .NET CLI:
   ```powershell
   dotnet build SpectraNetworkManager.sln -c Release
   ```
5. Run automated unit tests:
   ```powershell
   dotnet test tests/SpectraNetworkManager.Tests/SpectraNetworkManager.Tests.csproj -c Release
   ```

---

## 🔒 Privacy & Security Commitments

* **100% Local Execution**: All network inspections, DNS sinkhole operations, packet dissections, and AI analyses run entirely on your PC.
* **Zero Telemetry**: SpectraNetworkManager contains no tracking code, telemetry pings, advertising SDKs, or cloud dependencies.
* **Encrypted DNS**: Outbound DNS queries use DNS-over-HTTPS or DNS-over-TLS directly with your chosen independent upstream resolver.
* Review our complete policies in [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md).

---

## 📄 License & Credits

- Developed by **Biohazard Corp / Creator-NL**.
- Licensed under the open-source **[MIT License](../LICENSE)**.
- Official Website: [https://biohazard-corp.nl](https://biohazard-corp.nl)
- Interactive Online Demo: [https://biohazard-corp.nl/spectranetworkmanager.html](https://biohazard-corp.nl/spectranetworkmanager.html)
