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
