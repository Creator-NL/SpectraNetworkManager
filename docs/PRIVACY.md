# NetSentinel Privacy Policy & Transparency Commitment

**Effective Date:** Version 1.0  
**Project:** NetSentinel (Biohazard Corp / Creator-NL)  
**Repository:** https://github.com/Creator-NL/NetSentinel  

---

## 1. Core Commitment: Zero Telemetry, Zero Tracking

NetSentinel was built from day one on an uncompromising privacy promise:
* **No Telemetry:** We collect zero telemetry, diagnostic metrics, usage statistics, or analytics.
* **No Accounts or Registration:** You never create an account, provide an email address, or log in to use NetSentinel.
* **No Cloud Dependency:** NetSentinel runs entirely on your local machine. There are no proprietary backend servers or cloud relays.
* **100% Local Storage:** All network connection logs, ETW bandwidth figures, DNS history, and firewall rules are stored locally on your device in `%ProgramData%\NetSentinel`.

---

## 2. Complete Inventory of Network Activity

A firewall and security monitor must be completely transparent about its own network behavior. NetSentinel makes network requests **only** in the following four specific, transparent situations:

| Activity | Destination | Frequency | Configurable / Opt-Out |
| :--- | :--- | :--- | :--- |
| **Blocklist Downloads** | Configured blocklist URLs (e.g. StevenBlack hosts on GitHub/Raw) | On user request or configured auto-update interval | **Yes** — you choose which blocklist URLs to fetch, or disable external blocklists entirely. |
| **Reverse DNS Resolution** | Your configured upstream DNS resolver | In real-time as connections appear (cached locally) | **Yes** — uncheck "Resolve host names" on the main toolbar to disable all PTR lookups. |
| **Strict Mode Probe** | `http://www.msftconnecttest.com/connecttest.txt` | Once, during the 60-second Strict Mode confirmation test | **Yes** — only runs when explicitly activating Strict Mode. Checks basic HTTP connectivity to verify you are not accidentally locked out. |
| **Update Check** | `https://api.github.com/repos/Creator-NL/NetSentinel/releases/latest` | On startup or when clicking "Check for Updates" | **Yes** — toggleable in settings. Sends zero identifiers or tracking parameters (standard anonymous GET request). |

**NetSentinel makes no other network connections of any kind.**

---

## 3. Local Data Storage & Retention

All data recorded by NetSentinel remains strictly under your control:

* **Firewall Rules (`rules.json`):** Contains your explicit Allow and Block decisions.
* **DNS Sinkhole History (`dns-history.db`):** An embedded SQLite database recording local DNS lookups.
  * **Retention:** You can set retention periods (e.g., 7 days, 30 days) after which older records are automatically pruned.
  * **IP Anonymization:** Anonymize client IP addresses (`AnonymizeClientIps = true`).
  * **Domain Privacy:** Disable recording domain names (`DoNotStoreDomains = true`) to record only timestamps and response codes without preserving visited domain names.
* **Bandwidth & Traffic History (`network-history.db`):** Summarized byte counters per executable path.
* **Application Logs (`logs/netsentinel.log`):** Diagnostic logs with rolling 10 MB rotation (maximum 5 archives).

---

## 4. Diagnostic Sharing & Redaction

When using the **"Copy Support Info"** button to report an issue or bug:
* Personal user folder paths (such as `C:\Users\<YourUsername>\...`) are **automatically redacted** to `<redacted>` before copying to your clipboard.
* No private keys, credentials, or proprietary identifiers are included in diagnostic reports.

---

## 5. Summary

NetSentinel is designed to be a tool that serves **you**, the user. Your data is yours alone.
