# SpectraNetworkManager Manual Pre-Release Test Checklist

This checklist covers Windows-specific platform features that cannot be fully verified in automated headless environments (Windows Defender Firewall COM integration, WFP audit logging, strict-mode countdown watchdogs, and live DNS sinkholing).

> [!IMPORTANT]
> Always run this checklist inside an isolated Windows 10/11 Virtual Machine (Hyper-V, VirtualBox, or VMware) with a clean snapshot taken **before** installing or running SpectraNetworkManager. Revert to this snapshot after each test cycle.

---

## 1. Environment & Pre-Flight Checks

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **1.1** | Revert VM to clean baseline snapshot. | Clean OS state; no pre-existing SpectraNetworkManager files in `%LocalAppData%\SpectraNetworkManager`. | [ ] |
| **1.2** | Verify network connectivity in VM (`ping 1.1.1.1`, browse web). | Internet is accessible. | [ ] |
| **1.3** | Open Windows Defender Firewall with Advanced Security (`wf.msc`). | Outbound default rule is set to **Allow** (standard Windows default). No rules prefixed with `SpectraNetworkManager-`. | [ ] |
| **1.4** | Check elevated rights: Launch `SpectraNetworkManager.exe` **without** administrator rights. | App displays banner/warning indicating administrator rights are required for firewall modifications. | [ ] |
| **1.5** | Close and relaunch `SpectraNetworkManager.exe` with **Run as administrator**. | Administrator status confirmed; full functionality unlocked. | [ ] |

---

## 2. Firewall Rule Management

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **2.1** | In the Connections / Programs list, select an active program (e.g., `curl.exe` or `notepad.exe`) and click **Block**. | Rule is added to `Rules` tab. In `wf.msc`, an outbound block rule `SpectraNetworkManager-Block-...` is present. | [ ] |
| **2.2** | Attempt outbound connection with blocked program (`curl http://example.com`). | Connection fails immediately (blocked by firewall). | [ ] |
| **2.3** | Select the rule in SpectraNetworkManager and click **Delete** (or change to Allow). | Rule disappears from `wf.msc`. The program can connect again. | [ ] |
| **2.4** | Configure an "Allow only" rule with specific IP/port constraints. | Windows Firewall rule created with specified RemoteAddresses and RemotePorts. | [ ] |

---

## 3. Strict Mode & Safety Mechanisms

> [!WARNING]
> SpectraNetworkManager's strict mode blocks all outbound traffic by default and whitelists allowed programs. The safety net ensures you never get locked out.

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **3.1** | Click **Enable Strict Mode**. | Confirmation dialog appears displaying a 60-second countdown timer. `%LocalAppData%\SpectraNetworkManager\strict-mode.json` records pending state. | [ ] |
| **3.2** | **Test Case A (Confirmed):** Click **Keep Strict Mode** within 60s. | Strict mode remains active. Outbound default is Block. UI shows active indicator. Internet works for allowed programs. | [ ] |
| **3.3** | **Test Case B (Timeout Revert):** Disable strict mode, re-enable it, and **wait 60 seconds without clicking**. | Timer expires: SpectraNetworkManager automatically reverts firewall to normal outbound Allow. Full connectivity restored. | [ ] |
| **3.4** | **Test Case C (Crash Recovery):** Enable strict mode, and while countdown is ticking, force-kill SpectraNetworkManager (`taskkill /f /im SpectraNetworkManager.exe`). | Outbound firewall remains locked momentarily. Relaunch SpectraNetworkManager: Startup detector notices pending unconfirmed state and automatically restores previous firewall configuration. | [ ] |
| **3.5** | **Test Case D (Panic Button):** Enable strict mode and click **Panic Button** (Emergency Restore). | Immediately drops strict mode, sets outbound default back to Allow, removes all SpectraNetworkManager temporary rules, and restores connectivity. | [ ] |

---

## 4. Security Audit Log & Block Detection

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **4.1** | Ensure Filtering Platform connection auditing is enabled:<br>`auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable` | Command succeeds with "The command was successfully executed." | [ ] |
| **4.2** | Trigger a blocked connection using a blocked program. | Event Viewer -> `Windows Logs\Security` records Event ID **5157** (or **5152** for dropped packets). | [ ] |
| **4.3** | Inspect SpectraNetworkManager UI. | The blocked event appears in the Activity/Alerts feed with process path, destination IP, and port within 1-2 seconds. | [ ] |

---

## 5. DNS Sinkhole & Security Hardening

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **5.1** | In the **DNS** tab, check default settings (Listen: `127.0.0.1`, Port: `53` or `5353`, Block Mode: `NullAddress`). Click **Start DNS server**. | DNS server status changes to **RUNNING**. Green DNS badge appears in top header. | [ ] |
| **5.2** | Click **Test my DNS server**. | Built-in test connects directly to the server socket and reports:<br>1. Resolution of `example.com` (Pass)<br>2. Blocking of sample ad domain (Pass). | [ ] |
| **5.3** | Send query from loopback:<br>`Resolve-DnsName -Server 127.0.0.1 -Port <port> example.com` | Returns IP address (forwarded upstream). Query counters increment in UI. | [ ] |
| **5.4** | Query a blocked domain:<br>`Resolve-DnsName -Server 127.0.0.1 -Port <port> doubleclick.net` | Returns `0.0.0.0`. UI shows blocked query highlighted in magenta. | [ ] |
| **5.5** | Switch Block Mode to **NXDOMAIN**, save, and query `doubleclick.net` again. | Returns `DNS name does not exist` (NXDOMAIN). | [ ] |
| **5.6** | Test Firefox Canary DoH defense:<br>`Resolve-DnsName -Server 127.0.0.1 -Port <port> use-application-dns.net` | Returns NXDOMAIN (tells browsers not to bypass DNS with DoH). | [ ] |
| **5.7** | Test RFC 8482 ANY handling:<br>Send ANY query for `example.com`. | Server answers with minimal `HINFO` RR (CPU `RFC8482`), mitigating DNS amplification. | [ ] |
| **5.8** | **Open Resolver Protection:** Set listen address to `0.0.0.0`, save and restart. Query from a simulated non-private/external IP. | Server returns `REFUSED` (Rcode 5). Activity log records `Refused` ("query from public/untrusted client IP refused"). | [ ] |
| **5.9** | **Pause Blocking:** Click **Pause blocking** -> select **Pause for 5 minutes**. | Button updates to `Resume (04:59)` in amber. Cache flushes. Querying `doubleclick.net` now succeeds. Clicking `Resume` restores blocking immediately. | [ ] |

---

## 6. System DNS Switch & Safety Rollback

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **6.1** | Open DNS tab -> scroll to **POINT THIS PC TO SPECTRANETWORKMANAGER**. Click **Refresh adapters**. | Active physical adapters (Ethernet, Wi-Fi) appear checked. Disconnected, loopback, and virtual adapters are skipped or unchecked. | [ ] |
| **6.2** | Verify pre-switch DNS settings:<br>`Get-DnsClientServerAddress -InterfaceIndex <idx>` | Record current DNS servers and DHCP status. | [ ] |
| **6.3** | Ensure SpectraNetworkManager DNS server is RUNNING, then click **Point PC to SpectraNetworkManager...**. | 60-second confirmation dialog appears. Status banner shows **PENDING**. `%LocalAppData%\SpectraNetworkManager\dns-switch.json` and `dns-backup.json` are written. | [ ] |
| **6.4** | Check connectivity probe in confirmation dialog. | Reports `Connection check: OK. Both local SpectraNetworkManager DNS and Windows system resolver verified successfully.` | [ ] |
| **6.5** | While confirmation dialog is open, run in cmd/PowerShell:<br>`nslookup doubleclick.net`<br>*(do not specify server address)* | Resolves through `127.0.0.1` and returns `0.0.0.0` (ad blocked system-wide). | [ ] |
| **6.6** | Click **Keep SpectraNetworkManager DNS**. | Dialog closes. Status banner changes to **Active** (Cyan) showing protected adapters. | [ ] |
| **6.7** | Click **Restore original DNS**. | Sockets and adapters restored. `Get-DnsClientServerAddress` returns original servers and DHCP flag. Banner disappears. | [ ] |
| **6.8** | **Safety Test A (Timeout Rollback):** Click **Point PC to SpectraNetworkManager...** and **wait 60 seconds without clicking**. | Timer expires: SpectraNetworkManager automatically restores original adapter DNS settings. Internet connectivity maintained. | [ ] |
| **6.9** | **Safety Test B (Crash Recovery):** Click **Point PC to SpectraNetworkManager...**, and while countdown is ticking, force-kill SpectraNetworkManager:<br>`taskkill /f /im SpectraNetworkManager.exe` | Relaunch SpectraNetworkManager: Startup recovery detects unconfirmed pending state and automatically restores original adapter DNS settings. Alert displayed in activity feed. | [ ] |
| **6.10** | **Safety Test C (Panic Button):** Point PC to SpectraNetworkManager, confirm it, then click **PANIC: undo all SpectraNetworkManager changes**. | Immediately restores original system DNS on all adapters, removes temporary firewall rules, and turns off strict mode. | [ ] |

---

## 7. Teardown & Verification

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **7.1** | Stop the DNS server in SpectraNetworkManager. | Sockets released; port is freed. | [ ] |
| **7.2** | Inspect `wf.msc` rules. | No orphaned rules. | [ ] |
| **7.3** | Revert VM snapshot. | VM restored to clean baseline state for next test cycle. | [ ] |

---

**Tester:** `____________________`  
**Date:** `____________________`  
**OS Build:** `____________________`  
**Result:** `[  ] PASS    [  ] FAIL`

