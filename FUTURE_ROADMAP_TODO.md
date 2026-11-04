# 🚀 SpectraNetworkManager — Future Roadmap & Backlog To-Do List

This document tracks future features and advanced packet forensic capabilities inspired by deep-inspection tools like Wireshark, curated as a backlog for future development cycles.

---

## 🔬 Deep Packet Forensics & Stream Analysis (Wireshark-Grade Features)

### 1. Full TCP Stream Reassembly ("Follow TCP Stream")
- [ ] **Sequential Packet Stitching:** Implement an in-memory stream reassembler that tracks TCP sequence and acknowledgment numbers per socket pair (`LocalIP:Port <-> RemoteIP:Port`).
- [ ] **Dual-Color Dialogue Viewer:** Display full bidirectional conversations in a modal window:
  - 🔵 **Client Request** (outbound commands, HTTP headers, payloads in cyan)
  - 🟣 **Server Response** (inbound server data, API payloads in magenta)
- [ ] **Format Switcher:** Allow toggling between ASCII text, UTF-8, Raw Hex, and C/JSON string escape views.

### 2. File Carving & Stream Object Extraction
- [ ] **Automated Payload Extraction:** Extract files transferred over unencrypted streams or discovered within dissected protocols:
  - Images (`PNG`, `JPEG`, `WEBP`)
  - Web assets (`HTML`, `JS`, `CSS`, `JSON`)
  - Downloaded executables, DLLs, and archives (`ZIP`, `EXE`, `MSI`)
- [ ] **1-Click VirusTotal Hash Audit:** Instantly calculate the SHA-256 hash of extracted files and query VirusTotal or Spectra AI before saving to disk.

### 3. TLS / HTTPS Decryption Hub (SSLKEYLOGFILE Support)
- [ ] **Browser Keylog Listener:** Allow configuring or auto-detecting `SSLKEYLOGFILE` environment variables for Chrome, Edge, Brave, and Firefox.
- [ ] **On-The-Fly Decryption:** Decrypt captured TLS 1.2 / TLS 1.3 records using ephemeral master secrets.
- [ ] **Encrypted Payload Inspector:** Reveal decrypted HTTP/2 frames, REST API requests, and web socket frames without needing an external proxy like Fiddler.

### 4. Interactive Traffic & Latency Diagnostic Graphs
- [ ] **TCP Round-Trip Time (RTT) Graph:** Visual latency graphs per process to diagnose slow connections or packet drops.
- [ ] **Window Scaling & Buffer Bloat Analysis:** Track TCP window size anomalies and packet retransmissions.
- [ ] **Ladder Sequence Flow Diagrams:** Interactive visual timeline showing three-way handshake (`SYN` ➔ `SYN/ACK` ➔ `ACK`), TLS negotiation steps, and `FIN`/`RST` teardowns.

### 5. Specialized Protocol Dissectors
- [ ] **Windows SMB2 / SMB3:** Dissect LAN file share requests, file access events, and share tree connections.
- [ ] **Database Protocols:** Parse client queries for SQL Server (TDS), MySQL, and PostgreSQL.
- [ ] **VoIP & Audio Playback (RTP):** Detect RTP audio streams and provide in-app playback / export for VoIP troubleshooting.

---

## 🛡️ Advanced Defense & Automation Ideas

### 6. Automated Threat Hunting Triggers
- [ ] **Beaconing Detector:** Statistical detection for periodic background network pulses (e.g. malware C2 polling every 60 seconds).
- [ ] **DGA (Domain Generation Algorithm) Detector:** Algorithmic entropy analysis on DNS queries to identify randomly generated domain names.
- [ ] **Geo-Fencing Rules:** 1-click rules to block all inbound/outbound traffic to entire high-risk geographical regions or specific ASNs.

---

## 🤖 AI-Powered Ad & Countermeasure Investigator (Target: v2.1 Release)

An intelligent, on-demand assistant integrated into Spectra Browser Guard and SpectraNetworkManager that inspects stubborn, unknown, or obfuscated ads, anti-adblock overlays, and trackers, analyzes them with AI, and generates tailored blocking rules on the fly.

### 1. In-Browser "Investigate with AI" Picker
- [ ] **Context Menu & Popup Trigger:** Add an "Investigate Element with AI" option to the extension popup and right-click context menu.
- [ ] **Diagnostic Bundle Collector:** When the user clicks an unblockable ad or annoying overlay:
  - Captures the selected element's DOM subtree, tag hierarchy, attributes, and surrounding parent container classes.
  - Inspects applied CSS rules, z-indexes, fixed positions, and body lock styles (e.g. `overflow: hidden` or `pointer-events: none` caused by adblock walls).
  - Collects recent network requests and third-party script URLs initiated by the active tab.

### 2. High-Speed Native Messaging Telemetry Pipe
- [ ] **Zero-Overhead Transfer:** Pipe the diagnostic bundle from the browser extension directly to `SpectraNetworkManager.BrowserHost` using the established Native Messaging connection.
- [ ] **Privacy & Security First:** No API keys are stored in the browser extension; all network queries and reasoning execute on the local desktop application.

### 3. Dual AI Reasoning Engine (Local Ollama & Cloud Gemini)
- [ ] **Local LLM Support (Ollama):** Run lightweight local models (e.g., Llama 3, Phi-3, Mistral) for 100% offline and private ad analysis.
- [ ] **Cloud AI Support (Gemini API):** Optional fast cloud reasoning for deep analysis of complex anti-adblock scripts and obfuscated DOM traps.
- [ ] **Heuristic Pattern Synthesis:** AI determines:
  - Is the element a cosmetic ad container, a sponsored feed tile, or an anti-adblock detection modal?
  - What is the most resilient, non-fragile CSS selector (e.g. leveraging `:has()`, attribute wildcards, or structural paths) that removes the ad without breaking site functionality?
  - What network domain or script endpoint should be added to network filter rules?

### 4. Live Rule Injection & User Report
- [ ] **Instant Rule Push:** Deliver the AI-generated rule dynamically to the active browser tab via the existing `spectra_rules_updated` event — blocking the ad immediately without requiring a page refresh.
- [ ] **Custom Rule Database:** Save the validated rule in SpectraNetworkManager's custom user rules database with metadata (e.g., `"AI-generated for [domain] on [date]"`).
- [ ] **Friendly Diagnostic Summary:** Provide the user with a concise pop-up or notification:
  - What was identified (e.g., *"Detected obfuscated promotional banner from adservice.example"*).
  - Action taken (e.g., *"Generated CSS filter `div[class*='sponsored-tile']:has(a[href*='ad'])`"*).
  - Layout repair status (e.g., *"Restored page scrolling by clearing `overflow: hidden` from `<body>`"*).

---

## 📌 Status Tracker

| Feature | Category | Complexity | Target Release |
| :--- | :--- | :--- | :--- |
| **AI Ad Investigator & Neutralizer** | Smart Ad Blocking | Medium | v2.1 |
| **Follow TCP Stream** | Packet Forensics | Medium | Backlog (Future) |
| **File Carving & Export** | Packet Forensics | Medium | Backlog (Future) |
| **SSLKEYLOGFILE Decryption** | Advanced Forensics | High | Backlog (Future) |
| **TCP RTT & Ladder Diagrams** | Performance Diagnostics | Medium | Backlog (Future) |
| **SMB & Database Dissectors** | Protocol Analysis | High | Backlog (Future) |
| **Beaconing / DGA Hunter** | Active Defense | High | Backlog (Future) |
