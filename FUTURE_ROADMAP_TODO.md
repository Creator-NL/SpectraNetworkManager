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

## 📌 Status Tracker

| Feature | Category | Complexity | Target Release |
| :--- | :--- | :--- | :--- |
| **Follow TCP Stream** | Packet Forensics | Medium | Backlog (Future) |
| **File Carving & Export** | Packet Forensics | Medium | Backlog (Future) |
| **SSLKEYLOGFILE Decryption** | Advanced Forensics | High | Backlog (Future) |
| **TCP RTT & Ladder Diagrams** | Performance Diagnostics | Medium | Backlog (Future) |
| **SMB & Database Dissectors** | Protocol Analysis | High | Backlog (Future) |
| **Beaconing / DGA Hunter** | Active Defense | High | Backlog (Future) |
