# 🧪 SpectraNetworkManager v2.0 — Complete Testing & Verification Guide

Welcome to the **SpectraNetworkManager v2.0** testing guide! This document provides clear, step-by-step instructions for testing and validating all new features introduced in v2.0.

---

## 📑 Table of Contents
1. [Installation & Upgrade](#1-installation--upgrade)
2. [Multi-Language Switching (`Auto` / `English` / `Nederlands`)](#2-multi-language-switching)
3. [Spectra AI Threat Intelligence Engine](#3-spectra-ai-threat-intelligence-engine)
4. [Process Intelligence & Threat Attribution](#4-process-intelligence--threat-attribution)
5. [Port Scanner & Passive LAN Device Discovery](#5-port-scanner--passive-lan-device-discovery)
6. [4-Stage Active Defense Quarantine & System Guards](#6-4-stage-active-defense-quarantine--system-guards)
7. [Native Packet Inspector & Protocol Dissectors](#7-native-packet-inspector--protocol-dissectors)
8. [Smart TV & GSM Protection Hub](#8-smart-tv--gsm-protection-hub)
9. [Browser Guard & Manifest V3 Extension](#9-browser-guard--manifest-v3-extension)
10. [PANIC Recovery & Zero-Lockout Verification](#10-panic-recovery--zero-lockout-verification)

---

## 1. Installation & Upgrade

### Test Steps
1. Navigate to:  
   `installer\output\SpectraNetworkManager-v2.0.0-Setup.exe`
2. Double-click to run the setup installer.
3. Follow the installation wizard (you can install directly over any existing v1.0.x installation).
4. Launch **SpectraNetworkManager** from the desktop shortcut or Start menu.

### Expected Results
- Setup completes cleanly with version displayed as `2.0.0`.
- All previous firewall rules, DNS sinkhole settings, and client groups are automatically preserved.
- The application launches with Administrator rights and displays the new v2.0 header and tabs.

---

## 2. Multi-Language Switching

SpectraNetworkManager v2.0 features real-time language localization supporting **English**, **Nederlands (Dutch)**, and **Auto (System Culture)**.

### Test Steps
1. Look at the top toolbar (next to *Always on top* and *Alert sounds*).
2. Find the language selector dropdown: `[ 🌐 Auto (System) ▼ ]`.
3. Select **`🇳🇱 Nederlands`**:
   - Notice the navigation tabs change instantly:
     - `Verbindingen` (Connections)
     - `Programma's` (Programs)
     - `Opstarten` (Startup)
     - `Netwerkverkeer` (Traffic)
     - `Poortscanner` (Port Scanner)
     - `Pakketinspectie` (Packets)
     - `TV & Mobiel` (TV & Mobile)
     - `Spectra AI`
     - `Regels` (Rules)
     - `DNS Sinkhole`
     - `Firewall Blokkeerlijst` (Blocks)
   - Notice toolbar checkboxes and button tooltips update to Dutch.
4. Select **`🇬🇧 English`**:
   - Everything reverts immediately to English without restarting the app.
5. Select **`🌐 Auto (System)`**:
   - Automatically detects your Windows display language.

---

## 3. Spectra AI Threat Intelligence Engine

Spectra AI combines **C# ground-truth telemetry** (signatures, hashes, paths, parents, services) with an **optional local Ollama LLM** (`qwen2.5:7b`, etc.) or an **offline deterministic engine**.

### Test Steps
#### A. On-Demand Process Investigation
1. Click the **`Spectra AI`** tab in the top navigation bar.
2. In the target bar, click the **Target Process** dropdown:
   - Select any active program (e.g., `chrome.exe`, `explorer.exe`, or `SpectraNetworkManager.exe`).
3. Click the cyan **`✨ Run Investigation`** button:
   - You will see the `[⏳ Investigating...]` status indicator.
   - Within seconds, the **Active Investigation Card** populates:
     - **Verification Badge:** e.g., `🛡️ Verified System Binary` (Microsoft OS) or `✔ Verified Publisher`.
     - **Threat Risk Score:** Color-coded 0–100 score (e.g. `5/100` for system binaries, `15/100` for trusted publishers).
     - **Executive Summary:** Clear 1–2 sentence security assessment in English or Dutch.
     - **Telemetry Findings:** Bulleted breakdown of digital signatures, SHA-256 hash, parent PID, services, and listening ports.
     - **Identified Capabilities:** Cyan chips indicating behaviors like `Network Client`, `Service Host`, `Auto-Start Persistence`.
     - **Uncertainties & Blind Spots:** Highlights missing evidence or unverified aspects.

#### B. Investigating an Arbitrary Executable (.exe)
1. In the `Spectra AI` tab, click **`📁 Browse .exe...`**.
2. Select any executable file on disk (for example, `C:\Windows\notepad.exe` or an installer in your Downloads folder).
3. Click **`✨ Run Investigation`**:
   - If the file is in Downloads/Temp and unsigned, notice the badge changes to `⛔ Suspicious Location` or `⚠️ Unverified (Unsigned)`, and the risk score adjusts accordingly.

#### C. Testing 1-Click Context Menu Integration
1. Go to the **Connections** tab.
2. Right-click any active connection row.
3. Select **`✨ Investigate with Spectra AI`**:
   - SpectraNetworkManager switches directly to the `Spectra AI` tab, loads the target PID, and executes the investigation automatically!
4. Try the same from the **Programs**, **Startup**, **Rules**, or **Packets** tabs.

#### D. Testing Local Ollama (Optional)
1. If you have Ollama running locally (`http://127.0.0.1:11434`):
   - Type your model name in the **Model** box (default: `qwen2.5:7b`).
   - Click **`🔄 Test LLM`**.
   - Notice the status updates to: `🟢 Ollama Connected: [models]`.
2. If Ollama is not installed or closed:
   - Spectra AI seamlessly uses the **Offline Deterministic Engine** (`⚪ Offline Deterministic Engine`), guaranteeing 100% functionality with zero internet dependency!

#### E. Investigation History
1. Check the right-hand column: **Investigation History**.
2. Every past investigation is listed with its timestamp, target, verdict badge, risk score, and engine used.
3. Click on any past history item: notice the full investigation report reloads into the card instantly!
4. Click **`Clear History`** to reset the SQLite history database.

---

## 4. Process Intelligence & Threat Attribution

### Test Steps
1. Navigate to the **Connections** tab.
2. Click on any connection row to open the **Inspector Panel** at the bottom.
3. Observe the enriched metadata:
   - **Service / Parent Attribution:** e.g., for `svchost.exe`, you will see the exact hosted Windows Service (e.g., `Dnscache`, `WpnService`, `LanmanWorkstation`) rather than a mystery process.
   - **Parent Process:** Shows parent name and PID (e.g., `explorer.exe [PID 1234]`).
   - **Cryptographic Hash:** Shows the computed `SHA-256` hash.
4. **1-Click Threat Lookups:**
   - Click **`🛡️ VirusTotal`**: Opens your browser directly to VirusTotal's report for the executable's SHA-256 hash.
   - Click **`🚨 AbuseIPDB`**: Looks up the remote IP address for abuse reports and botnet activity.
   - Click **`🔎 Shodan`**: Explores the remote host's open ports and SSL certificate details.
   - **Offline GeoIP & ASN:** Notice IP addresses display country flags and autonomous system names (e.g., `US · Cloudflare DNS (AS13335)`).

---

## 5. Port Scanner & Passive LAN Device Discovery

### Test Steps
1. Click the **`Port Scanner`** tab.
2. **Subnet Discovery:**
   - Verify that your local subnet is automatically selected (e.g. `192.168.1.0/24`).
   - Click **`▶ Scan Subnet (ARP/Ping)`**:
     - Scans your local network safely using RFC1918 private IP bounds.
     - Discovered devices populate the table: IP, MAC Address, Hardware Vendor, and classified Device Type.
     - Note the hardware icons: 🖥️ Workstation, 📺 Smart TV, 📱 Mobile Phone, 🌐 Router/Gateway, ⚡ Crypto Miner (e.g. Byteaxe).
3. **Port Scanning:**
   - Select a device from the list, or type `127.0.0.1` (your local PC) in the target box.
   - Select scan profile: **`Top 20 Ports`** or **`Top 100 Ports`**.
   - Click **`▶ Scan Ports`**:
     - Fast scanning with bounded concurrency (24 sockets) and 800ms timeouts.
     - Open ports appear in the results list with service names and captured banners.
4. **Safety & Cancellation:**
   - Try entering an external internet IP (e.g., `8.8.8.8`) and clicking scan:
     - Notice SpectraNetworkManager **safely rejects external targets** to prevent accidental remote port scanning.
   - During a scan, click **`⏹ Stop`**:
     - Notice the scan cancels within `< 250 ms`.
5. **Export:**
   - Click **`Export CSV`** or **`Export JSON`** to save your device and port inventory.

---

## 6. 4-Stage Active Defense Quarantine & System Guards

### Test Steps
#### A. Testing Reversible 4-Stage Quarantine
> [!NOTE]
> To test quarantine safely, launch a harmless program (such as `notepad.exe` or a secondary browser window).

1. In the **Connections** or **Programs** tab, locate your test program.
2. Right-click and choose **`🛡️ 4-Stage Quarantine Program...`**.
3. Read the confirmation dialog explaining the 4 stages:
   - **Stage 1:** Tears down active TCP sockets and terminates running process instances.
   - **Stage 2:** Stops dedicated Windows services (if applicable).
   - **Stage 3:** Disables Auto-Start / Registry Run entries.
   - **Stage 4:** Creates Inbound + Outbound Windows Firewall block rules.
4. Click **`Yes`**:
   - The program is immediately neutralized and closed.
   - A snapshot is saved in the **Quarantine Vault** (`quarantine-vault.json`).
5. **1-Click Restore / Rollback:**
   - Right-click the program in the Programs or Rules view and select **`🔄 Restore from Quarantine...`**.
   - Confirm the restore: the firewall rules are cleanly removed, auto-start entries re-enabled, and the program is restored to normal!

#### B. Testing Operating System Binary Protection
1. Find a core Windows system process in the list (e.g., `svchost.exe`, `explorer.exe`, or `lsass.exe`).
2. Right-click and choose **`🛡️ 4-Stage Quarantine Program...`**.
3. Notice that SpectraNetworkManager **refuses to quarantine core OS binaries**, protecting your system from accidental lockouts!

#### C. System Tamper Monitors
1. **Hosts File Monitor:** Check the DNS sinkhole / Rules status bar. If any third-party app or malware modifies `C:\Windows\System32\drivers\etc\hosts`, Spectra alerts you immediately with a 1-click clean template restore option.
2. **Browser DoH Guard:** Go to DNS settings and view the Browser DoH indicator. Toggling the guard applies enterprise group policies to Chrome, Edge, Brave, and Firefox to stop browsers from bypassing your local DNS sinkhole.

---

## 7. Native Packet Inspector & Protocol Dissectors

### Test Steps
1. Navigate to the **`Packets`** tab.
2. In the interface dropdown, select your active network adapter (e.g. Ethernet or Wi-Fi).
3. Click **`▶ Start Capture`**:
   - The status ticker turns green: showing total packets, packets/sec, and payload bandwidth rate.
4. Generate network activity:
   - Open a browser and visit websites (e.g. `github.com`, `wikipedia.org`, or any news site).
5. **Protocol Dissection Table:**
   - Observe live packets appearing in real time (batched at 250ms for 60 FPS smooth scrolling).
   - Look at the **PROTO** and **HOST / SNI** columns:
     - **TLS / HTTPS:** Displays the exact Server Name Indication (SNI) domain (e.g., `api.github.com`).
     - **DNS:** Displays queried domain names and record types (e.g., `A`, `AAAA`).
     - **TCP Flags:** Shows connection handshake flags (`[SYN]`, `[SYN, ACK]`, `[FIN, ACK]`, `[ACK]`).
6. **Filtering:**
   - Click the filter buttons: `ALL`, `TCP`, `UDP`, `TLS / HTTPS`, `DNS`, `HTTP`.
   - Type in the search box to filter by host, IP, or process name.
7. **Dissected Inspector & Hex Stream Preview:**
   - Click on any packet row:
     - The bottom left panel displays the **Protocol Tree** (Ethernet Frame -> IP Header -> TCP/UDP -> TLS/Payload).
     - The bottom right panel displays the **16-byte Hex Dump & ASCII stream preview**.
8. **Wireshark Export:**
   - Click **`💾 Export .pcapng`**:
   - Save the file and open it in Wireshark: notice all timestamps, interfaces, and packet payloads open with zero errors.

---

## 8. Smart TV & GSM Protection Hub

### Test Steps
1. Navigate to the **`TV & Mobile`** tab.
2. **Device Discovery & Status Badges:**
   - Check the discovered LAN devices. Each device displays an informative protection status badge:
     - 🟢 **Direct Protected:** Device is querying Spectra directly (`Last query: 5s ago`).
     - 🟡 **Gateway Routed:** Your router is forwarding queries (`192.168.1.1`). Per-device rules require pointing the TV/GSM Wi-Fi DNS directly to Spectra's IP.
     - ⚪ **Bypass / Inactive:** Device is on Wi-Fi, but not querying Spectra (hardcoded DNS or DoH).
     - ⚠️ **DoH Bypass Risk:** Device is contacting known public DoH resolvers (`dns.google`, `cloudflare-dns.com`).
3. **1-Click Multi-Vendor Telemetry Shields:**
   - Right-click a Smart TV in the table -> **`📺 Apply Smart TV ACR Shield`**:
     - Automatically blocks Automatic Content Recognition (ACR) viewing trackers and ad networks for Samsung Tizen, LG webOS, Roku OS, Sony Bravia, Android TV, Xiaomi, and Apple TV!
   - Right-click a phone in the table -> **`📱 Apply Mobile Ad & Tracker Shield`**:
     - Automatically blocks mobile attribution trackers (Adjust, AppsFlyer, Branch, Kochava) and in-app ad SDKs (UnityAds, AppLovin, IronSource).
4. **Onboarding Guides:**
   - Right-click any device -> **`⚙️ Show DNS Setup Steps for this Device`**:
     - Displays step-by-step Wi-Fi DNS setup instructions specific to that platform (Samsung, LG, Android, iOS, etc.).
5. **GSM Mobile Companion Pairing:**
   - Click **`📱 Pair GSM Device`**:
     - A modal appears showing a high-resolution QR code and a 6-digit numeric PIN with a 60-second live countdown.
     - Check the *"Allow Mobile Rule Changes"* option if you want write permission from your phone.
     - Scan the QR code with your smartphone camera while connected to the same Wi-Fi.

---

## 9. Browser Guard & Manifest V3 Extension

### Test Steps
1. Navigate to the **`Browser Guard`** tab.
2. Check the **Native Messaging Host** status:
   - Displays whether the host manifest is registered in Windows Registry for Chrome, Edge, and Firefox.
3. **Install the Extension in Your Browser:**
   - **Chrome / Edge / Brave:**
     1. Open `chrome://extensions` (or `edge://extensions`).
     2. Turn on **Developer mode** (top right switch).
     3. Click **Load unpacked**.
     4. Browse to:  
        `extensions\spectra-browser-guard\`  
        *(also bundled in `publish\app\extensions\spectra-browser-guard`)*.
   - **Firefox:**
     1. Open `about:debugging#/runtime/this-firefox`.
     2. Click **Load Temporary Add-on...**.
     3. Select the `manifest.json` file inside `extensions\spectra-browser-guard\`.
4. **Testing Video & URL Blocking:**
   - In the `Browser Guard` tab, verify that **`🛡️ Block YouTube Shorts`** is checked.
   - Open your browser and navigate to any YouTube Shorts URL (e.g. `youtube.com/shorts/...`):
     - The video stream is blocked via Manifest V3 `declarativeNetRequest` dynamic rules.
     - The video player is replaced with a clean, dark cybernetic placeholder:  
       *"Video Blocked by SpectraNetworkManager"* with an **"Allow Once"** override button!
5. **Adding Custom Blocking Rules:**
   - In the `Browser Guard` tab, enter a title (e.g. `Block Twitch Streams`), a URL pattern (e.g. `*://*.twitch.tv/*`), select Resource Type (`media` or `all`), and click **`+ Add Rule`**.
   - Notice the rule takes effect immediately in your browser.

---

## 10. PANIC Recovery & Zero-Lockout Verification

A core design principle of SpectraNetworkManager is **100% reversible changes with zero risk of lockouts**.

### Test Steps
1. Apply several rules, strict mode, or quarantine an app.
2. Go to the **Programs** tab.
3. Look for the magenta button in the top right:  
   **`PANIC: undo all SpectraNetworkManager changes`**.
4. Click **PANIC**:
   - Instantly disables strict mode.
   - Deletes every Windows Firewall rule created by Spectra.
   - Restores default outbound firewall policies.
   - Automatically un-quarantines any quarantined processes and services.
   - Restores network adapters to their original state.
5. Verify your internet connection remains 100% functional.

---

## 🏁 Verification Checklist

- [ ] **Setup installer** upgrades cleanly without losing existing settings.
- [ ] **Language switcher** toggles dynamically between English and Nederlands.
- [ ] **Spectra AI** generates accurate risk scores, badges, and findings for running processes and arbitrary `.exe` files.
- [ ] **Local Ollama** connects and generates structured reports, or gracefully falls back to the deterministic engine when offline.
- [ ] **Context menus** throughout the app allow 1-click `"Investigate with Spectra AI"`.
- [ ] **Process Intelligence** displays parent processes, svchost services, SHA-256, and VirusTotal/AbuseIPDB links.
- [ ] **Port Scanner** discovers LAN hosts and scans ports safely within private IP bounds.
- [ ] **4-Stage Quarantine** neutralizes target programs with 100% reversible rollback, while protecting OS core files.
- [ ] **Packet Inspector** captures live packets, dissects TLS SNI, and exports standard `.pcapng` files.
- [ ] **TV & Mobile Hub** displays protection badges and applies ACR / mobile tracker blocklists.
- [ ] **Browser Guard** blocks YouTube Shorts and video streams using Manifest V3 dynamic rules.
- [ ] **PANIC button** restores all network and firewall settings in 1 click.

---

*Thank you for testing SpectraNetworkManager v2.0! If you spot any unexpected behavior or have ideas for further polish, please let me know.*
