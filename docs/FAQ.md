# SpectraNetworkManager Frequently Asked Questions (FAQ)

---

### 1. What is SpectraNetworkManager?
SpectraNetworkManager is a free, open-source security tool for Windows combining three core capabilities:
1. **Live Network Activity Monitor:** Real-time visibility into all active TCP/UDP connections, listening ports, process paths, transfer speeds, and digital signatures.
2. **Outbound Application Firewall:** Control which applications can communicate outbound via precise Windows Firewall rules.
3. **Local DNS Sinkhole:** A high-speed, local DNS server (similar to Pi-hole) that blocks ads, trackers, and telemetry domains before they leave your PC or home network.

---

### 2. Is SpectraNetworkManager really 100% free?
**Yes.** SpectraNetworkManager has no paid tiers, no premium features, no subscriptions, and no advertisements. It is completely free and open-source software provided to the public.

---

### 3. Does SpectraNetworkManager collect any telemetry?
**No.** SpectraNetworkManager collects zero telemetry, zero analytics, and zero personal information. All network logs and DNS queries stay exclusively on your local machine. See [PRIVACY.md](PRIVACY.md) for full details.

---

### 4. What is the difference between the 3 operating modes?
* **Watch Only (Default & Recommended):** SpectraNetworkManager observes and logs connections and DNS lookups. Nothing is blocked unless you explicitly create a rule. This is the safest mode for regular everyday use.
* **Ask Mode:** SpectraNetworkManager monitors traffic and displays a prompt whenever an unfamiliar program accesses the network, allowing you to Allow or Block it.
* **Strict Mode:** SpectraNetworkManager changes Windows Firewall's outbound default to Block. Only programs you have explicitly allowed or trusted (and essential Windows services like DHCP and DNS) can connect.

---

### 5. What should I do if a program stops working or loses internet access?
If a game, browser, or tool suddenly cannot connect:
1. Open SpectraNetworkManager and go to the **Firewall blocks** tab or **Programs** tab.
2. Look for the application in question (recently blocked apps appear highlighted).
3. Select the program and click **Allow** (or right-click and choose **Allow**).
4. If you previously created a Block rule by mistake, switch to the **Rules** tab, locate the rule, and click **Forget decision**.

---

### 6. What does the PANIC button do?
The **PANIC** button (located on the top bar and in the system tray menu) is an emergency reset switch:
* Reverts Windows Firewall outbound policy back to standard Windows defaults (Allow).
* Deletes all firewall rules SpectraNetworkManager created.
* Restores system DNS settings on all network adapters back to their original configuration.
* Clears temporary block decisions.

---

### 7. How do I recover if I am locked out or the app crashes?
If network connectivity is impaired and you cannot access the main interface:
* **Option 1 (Start Menu):** Launch **"SpectraNetworkManager (Safe Recovery Mode)"** from the Windows Start menu.
* **Option 2 (Command Line):** Run:
  ```powershell
  SpectraNetworkManager.exe --safe
  ```
  This immediately executes the emergency restore without launching the UI, restores all network settings, and confirms recovery.
* **Option 3 (Administrator Command Prompt):** Run:
  ```cmd
  netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
  ```

---

### 8. How does the DNS Sinkhole work?
When active, SpectraNetworkManager runs a lightweight, multithreaded DNS server on your machine. You can point your network adapter (or entire home router) to SpectraNetworkManager's IP address. When applications resolve domain names, SpectraNetworkManager inspects the domain against blocklists (e.g., ad and telemetry lists). If blocked, it returns `0.0.0.0` or `NXDOMAIN`, preventing connections to tracking servers before any traffic is sent.

---

### 9. Can I run SpectraNetworkManager alongside Windows Defender or another antivirus?
**Yes.** SpectraNetworkManager does not replace Windows Defender or third-party antivirus software. Antivirus programs scan files on disk and detect malware payloads; SpectraNetworkManager monitors and regulates network socket traffic and DNS queries. They complement each other.

---

### 10. How do I uninstall SpectraNetworkManager cleanly?
To uninstall SpectraNetworkManager:
1. Open Windows **Settings** > **Installed apps** (or Control Panel > Programs and Features).
2. Select **SpectraNetworkManager** and click **Uninstall**.
3. The SpectraNetworkManager uninstaller automatically executes safe cleanup: it removes all SpectraNetworkManager firewall rules, restores outbound defaults to Allow, restores your original network adapter DNS settings, stops and removes the background service, and asks if you wish to retain or delete your local rule files and history database.

---

### 11. Can I try out SpectraNetworkManager before downloading?
**Yes.** You can test the interactive connection monitor, firewall rule generator, DNS sinkhole simulator, and strict mode safety countdown directly in your browser at [https://biohazard-corp.nl/spectranetworkmanager.html](https://biohazard-corp.nl/spectranetworkmanager.html). Visit [https://biohazard-corp.nl](https://biohazard-corp.nl) for more free tools and updates.

---

### 12. How do I view or undo domains I have manually blocked or allowed?
* **Directly in the Live Query Log:** Click any query in the DNS tab that you have manually blocked. The Domain Inspector at the bottom will display a **`[ 🚫 CUSTOM BLOCKED RULE ]`** badge and an amber **`[ ✕ Remove from Blocklist (Undo) ]`** button. Clicking it removes the rule and unblocks the domain immediately.
* **Via the Custom Rules Manager:** Click **`[ 🛡️ Custom Rules ]`** on the DNS toolbar (or right-click the log and choose *Manage Custom Rules...*). This opens a dedicated window listing all domains you have personally blocked or whitelisted, complete with a real-time search filter and 1-click **Remove** buttons.

---

### 13. How are blocklists stored, and do I need to re-download them after an update?
**No, you do not need to re-download them.** Downloaded subscription blocklists are stored permanently as plaintext files in `%ProgramData%\SpectraNetworkManager\blocklists\`. SpectraNetworkManager preloads these files into memory immediately on startup (83,000+ domains in milliseconds). When you install updates, existing downloaded lists and custom rules are preserved automatically.

---

### 14. Why do YouTube videos buffer if I block `googlevideo.com`?
YouTube serves both advertisements and the actual video/audio stream segments from `*.googlevideo.com` servers. Blocking this domain prevents video playback or causes videos to buffer indefinitely. SpectraNetworkManager's Domain Intelligence Inspector flags `googlevideo.com` with a **Caution: May Break Features** warning to prevent accidental breakage.

---

### 15. How does the 60-second safety rollback protect my network connection?
Whenever you point your network adapters (Wi-Fi, Ethernet) to SpectraNetworkManager or enable Strict Mode, SpectraNetworkManager creates a backup of your current working configuration and starts a 60-second safety timer while testing internet connectivity. If you do not click Confirm, if connectivity is lost, or if the application closes unexpectedly, all DNS and firewall settings are automatically rolled back to your previous working state.

---

### 16. What is the 5-Stage Active Quarantine Vault?
The 5-Stage Quarantine Vault is an active defense capability that neutralizes hostile, unauthorized, or suspicious software across five consecutive containment rings:
1. **Process & Socket Kill:** Forcefully terminates all active process instances and drops all active TCP/UDP sockets immediately.
2. **Execution Lockout (IFEO):** Configures an Image File Execution Options debugger redirect (`systray.exe`), preventing Windows from ever launching the executable again even if a user or script double-clicks it.
3. **Service Disabling:** Discovers and stops any Windows Services hosted by the executable and disables their startup type.
4. **Auto-Start Removal:** Disables matching auto-start entries in the Registry, Startup folders, and Task Scheduler.
5. **Firewall Block:** Registers Windows Firewall rules dropping all inbound and outbound traffic.

Every quarantined item is safely recorded in the **Quarantine** tab with full reversible 1-click restore.

---

### 17. How does the Spectra AI Threat Intelligence Engine and Chat work?
Spectra AI analyzes running processes, startup items, or network sockets by extracting cryptographic evidence (Authenticode digital signature verification, publisher certificate, system directory validation, and SHA-256 hash calculation) combined with observed network telemetry (ports, remote endpoints, DNS lookups). It assigns a **0–100 Risk Score** and a clear threat verdict (`Safe`, `Low Risk`, `Suspicious`, `Malicious`).

You can also use the interactive **`💬 Ask Spectra AI`** chat thread to ask follow-up questions (e.g. *"Is this safe to run?"*, *"Why does this program connect to the internet?"*, *"What happens if I block it?"*). If you run **Ollama** locally (`127.0.0.1:11434`), Spectra AI leverages your local neural model for conversational analysis. If Ollama is offline or not installed, Spectra AI's built-in **Deterministic Security Engine** delivers instant, factual offline answers based on the audited evidence.

---

### 18. What does Spectra Browser Guard do and how does it block YouTube ads?
Spectra Browser Guard is a lightweight Manifest V3 extension for **Google Chrome**, **Microsoft Edge**, and **Mozilla Firefox** paired with a local Native Messaging Host (`SpectraNetworkManager.BrowserHost.exe`). It intercepts web requests inside the browser with zero network latency using declarative rules (`declarativeNetRequest`), suppressing:
* YouTube pre-roll, mid-roll, and banner advertisements.
* Video ad-tracking telemetry beacons.
* In-video promo cards and annotations.
* Distracting YouTube Shorts feeds (optional toggle).
* Custom elements blocked via the in-page visual Element Picker.

---

### 19. How do I protect Smart TVs, phones, or IoT devices on my local network?
Open the **TV & Mobile** tab in SpectraNetworkManager:
1. **QR-Code Pairing:** Scan the on-screen QR code with your smartphone to open the mobile companion dashboard.
2. **DNS Protection:** Set your TV or phone's DNS server to your PC's local LAN IP address (or enable the built-in DHCP server in the TV & Mobile settings).
3. **3-in-1 Hub:** You can route device traffic through the built-in HTTP/HTTPS Proxy (port 8888) or the L3 Gateway Router.
4. **Independent Rules:** Manage phone and smart TV blocking rules separately (`tv-mobile-rules.json`), ensuring aggressive ad blocking on your TV never interferes with PC browsing or gaming.

---

### 20. What is Self-Healing & Protected Programs?
Certain critical system components (such as Microsoft Edge WebView2, local Ollama runtime, and core Windows binaries) are essential for operating system stability and the SpectraNetworkManager UI itself. SpectraNetworkManager includes automated self-healing guards:
* Protected binaries can never be accidentally locked out via IFEO or quarantined.
* On startup, the application automatically scans and heals any orphaned or stale IFEO execution redirects left behind by uninstalled software.
* The uninstaller automatically sweeps and removes all execution lockouts cleanly.



