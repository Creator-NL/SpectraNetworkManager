# NetSentinel Manual Pre-Release Test Checklist

This checklist covers Windows-specific platform features that cannot be fully verified in automated headless environments (Windows Defender Firewall COM integration, WFP audit logging, strict-mode countdown watchdogs, and live DNS sinkholing).

> [!IMPORTANT]
> Always run this checklist inside an isolated Windows 10/11 Virtual Machine (Hyper-V, VirtualBox, or VMware) with a clean snapshot taken **before** installing or running NetSentinel. Revert to this snapshot after each test cycle.

---

## 1. Environment & Pre-Flight Checks

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **1.1** | Revert VM to clean baseline snapshot. | Clean OS state; no pre-existing NetSentinel files in `%LocalAppData%\NetSentinel`. | [ ] |
| **1.2** | Verify network connectivity in VM (`ping 1.1.1.1`, browse web). | Internet is accessible. | [ ] |
| **1.3** | Open Windows Defender Firewall with Advanced Security (`wf.msc`). | Outbound default rule is set to **Allow** (standard Windows default). No rules prefixed with `NetSentinel-`. | [ ] |
| **1.4** | Check elevated rights: Launch `NetSentinel.exe` **without** administrator rights. | App displays banner/warning indicating administrator rights are required for firewall modifications. | [ ] |
| **1.5** | Close and relaunch `NetSentinel.exe` with **Run as administrator**. | Administrator status confirmed; full functionality unlocked. | [ ] |

---

## 2. Firewall Rule Management

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **2.1** | In the Connections / Programs list, select an active program (e.g., `curl.exe` or `notepad.exe`) and click **Block**. | Rule is added to `Rules` tab. In `wf.msc`, an outbound block rule `NetSentinel-Block-...` is present. | [ ] |
| **2.2** | Attempt outbound connection with blocked program (`curl http://example.com`). | Connection fails immediately (blocked by firewall). | [ ] |
| **2.3** | Select the rule in NetSentinel and click **Delete** (or change to Allow). | Rule disappears from `wf.msc`. The program can connect again. | [ ] |
| **2.4** | Configure an "Allow only" rule with specific IP/port constraints. | Windows Firewall rule created with specified RemoteAddresses and RemotePorts. | [ ] |

---

## 3. Strict Mode & Safety Mechanisms

> [!WARNING]
> NetSentinel's strict mode blocks all outbound traffic by default and whitelists allowed programs. The safety net ensures you never get locked out.

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **3.1** | Click **Enable Strict Mode**. | Confirmation dialog appears displaying a 60-second countdown timer. `%LocalAppData%\NetSentinel\strict-mode.json` records pending state. | [ ] |
| **3.2** | **Test Case A (Confirmed):** Click **Keep Strict Mode** within 60s. | Strict mode remains active. Outbound default is Block. UI shows active indicator. Internet works for allowed programs. | [ ] |
| **3.3** | **Test Case B (Timeout Revert):** Disable strict mode, re-enable it, and **wait 60 seconds without clicking**. | Timer expires: NetSentinel automatically reverts firewall to normal outbound Allow. Full connectivity restored. | [ ] |
| **3.4** | **Test Case C (Crash Recovery):** Enable strict mode, and while countdown is ticking, force-kill NetSentinel (`taskkill /f /im NetSentinel.exe`). | Outbound firewall remains locked momentarily. Relaunch NetSentinel: Startup detector notices pending unconfirmed state and automatically restores previous firewall configuration. | [ ] |
| **3.5** | **Test Case D (Panic Button):** Enable strict mode and click **Panic Button** (Emergency Restore). | Immediately drops strict mode, sets outbound default back to Allow, removes all NetSentinel temporary rules, and restores connectivity. | [ ] |

---

## 4. Security Audit Log & Block Detection

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **4.1** | Ensure Filtering Platform connection auditing is enabled:<br>`auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable` | Command succeeds with "The command was successfully executed." | [ ] |
| **4.2** | Trigger a blocked connection using a blocked program. | Event Viewer -> `Windows Logs\Security` records Event ID **5157** (or **5152** for dropped packets). | [ ] |
| **4.3** | Inspect NetSentinel UI. | The blocked event appears in the Activity/Alerts feed with process path, destination IP, and port within 1-2 seconds. | [ ] |

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

## 6. Teardown & Verification

| Step | Action | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- |
| **6.1** | Stop the DNS server in NetSentinel. | Sockets released; port is freed. | [ ] |
| **6.2** | Inspect `wf.msc` rules. | No orphaned rules. | [ ] |
| **6.3** | Revert VM snapshot. | VM restored to clean baseline state for next test cycle. | [ ] |

---

**Tester:** `____________________`  
**Date:** `____________________`  
**OS Build:** `____________________`  
**Result:** `[  ] PASS    [  ] FAIL`
