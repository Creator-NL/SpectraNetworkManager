# SpectraNetworkManager

Windows network monitor + per-application firewall + DNS sinkhole, written in C# / .NET 8 (works in Visual Studio 2022 17.8+).

## Status: Phase 4 - Release Readiness & Packaging Complete

| Project / Component | Purpose |
|---|---|
| `SpectraNetworkManager.App` | **WPF UI front-end**: Real-time traffic, Programs, Rules, DNS sinkhole, Firewall blocks, First-Run Wizard, Update Checker |
| `SpectraNetworkManager.Core` | Platform-independent models, rule planners (IPv4 + IPv6), DNS engine, IPC protocol, update checker, logging, settings |
| `SpectraNetworkManager.Platform.Windows` | Native IP Helper, native Authenticode verification (WinVerifyTrust + CryptCATAdmin), real-time WFP drop events, Firewall enforcer |
| `SpectraNetworkManager.Engine` | **Windows Service**: Background LocalSystem coordinator for firewall enforcement, WFP events, and DNS sinkholing |
| `installer/` | Inno Setup production installer script (`SpectraNetworkManager.iss`) and automated `build-package.ps1` pipeline |
| `docs/` | User documentation: [PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md), [FAQ.md](FAQ.md) |

## Run it
Open `SpectraNetworkManager.sln` in Visual Studio 2022. **`SpectraNetworkManager.App` must be the startup project** (right-click it in
Solution Explorer -> *Set as Startup Project*); class libraries such as Core cannot be started directly.
Then press F5.

For the full picture run Visual Studio (or the built `SpectraNetworkManager.exe`) **as Administrator**: system services then show
their program names, and the Firewall blocks view can read the Security log.

Console spike: `dotnet run --project src/SpectraNetworkManager.Spike -- --watch` (also `--all`, `--blocks`, `--blocks --packets`).

## Learning mode, Ask mode and decisions
- Nothing is blocked automatically. Programs that reach the internet without a decision are marked **NEW** (magenta) in the Programs view and announced once in the live events list (amber `!`).
- **Ask mode** (checkbox, on by default): when such a program appears, a bar at the top asks **Allow / Block... / Later** and the taskbar button flashes.
  SpectraNetworkManager cannot pause the program's very first connection (that would need a kernel driver), so the question comes right after it. Programs already running when SpectraNetworkManager starts are not asked about, and Windows' own programs are listed but never asked about.
- **Allow** records "this program is OK" (Windows already allows it; nothing changes in the firewall).
- **Block...** lets you choose *incoming + outgoing*, *outgoing only* or *incoming only*, then adds Windows Firewall rules for that exact exe. Needs Administrator.
- **Rules view** lists every decision, including for programs that are not running, and checks that the Windows Firewall really has the matching rules (**MISSING** = they were removed outside SpectraNetworkManager). Use it to switch a decision to Allow or to Forget it.
- **Forget decision** removes your decision and, for a block, the firewall rules.
- **PANIC: undo all SpectraNetworkManager changes**: switches strict mode off, deletes every firewall rule SpectraNetworkManager created, and restores original system DNS.
- **Safe Recovery Mode (`--safe`)**: start with `SpectraNetworkManager.exe --safe` (or via the Start Menu shortcut "SpectraNetworkManager (Safe Recovery Mode)") to immediately restore firewall defaults, remove all rules, and restore system DNS offline without opening the main window.
- **Windows System Tray**: right-click the shield tray icon for quick access to pause/resume DNS blocking, check for updates, or trigger Panic restore.
- Windows system programs (anything under the Windows folder) cannot be blocked from here yet.
- Careful with shared components: blocking something like `msedgewebview2.exe` also breaks every app that uses it (for example the new Outlook).
- Every rule SpectraNetworkManager creates is in the Windows Firewall group **SpectraNetworkManager** (visible in "Windows Defender Firewall with Advanced Security"; the name starts with `SpectraNetworkManager block`). Deleting that group by hand also undoes everything.
- Your decisions and settings are stored in `%ProgramData%\SpectraNetworkManager` (with automatic migration from `%LocalAppData%\SpectraNetworkManager`).

## Blocking exactly what you want (Block... dialog)
- **Direction**: incoming and outgoing, outgoing only, or incoming only.
- **What to block**:
  - *Everything*: the program gets no network access in that direction.
  - *Only traffic that matches*: block only the protocol / ports / addresses you list (e.g. TCP port 25 so a program cannot send mail; or one address range).
  - *Allow ONLY traffic that matches*: block everything except what you list (e.g. "only port 443" for a program that should only browse the web).
- **Ports** mean the service port: the remote port for outgoing traffic, your own local port for incoming traffic. Examples: `443`, `80,443,8000-8100`.
- **Addresses** are always the other side: `203.0.113.7`, `10.0.0.0/8`, `198.51.100.1-198.51.100.50`. IPv6 addresses and the keywords `LocalSubnet`, `DNS`, `DHCP`, `DefaultGateway`, `WINS` work with *Only traffic that matches*, but not with *Allow ONLY* (that mode needs to invert the list, which is only done for IPv4).
- **Keep my local network reachable** (Allow ONLY): traffic to your own PC, router and LAN devices (private, loopback, multicast ranges) is never blocked.
- Windows Firewall lets a block override an allow, so "Allow ONLY" is built as blocks for everything *else* (the complement of your ports/addresses). The dialog shows how many firewall rules that creates.
  An "Allow ONLY" restriction on protocol covers TCP and UDP; other protocols such as ICMP are not touched.
- **Rules view**: the BLOCKS column shows the scope; **Edit block...** changes it; the FIREWALL column compares the number of rules that should exist with what Windows really has (`active`, `PARTIAL 1/3`, `MISSING`).
- If creating the rules fails half-way, the ones already created are removed again, so a program is never left half-blocked.

## DNS sinkhole (DNS tab) - the Pi-hole part
A DNS server inside SpectraNetworkManager: it answers the DNS questions of your PC (and optionally your network), **blocks** names on block lists, caches answers and forwards everything else
to your upstream servers (default Quad9 9.9.9.9 and Cloudflare 1.1.1.1; change them in the settings).

- **Start**: DNS tab > *Start DNS server*. Then *Update block lists* (downloads the lists from the settings; the default is the StevenBlack unified hosts list).
  Check it from a command prompt: `nslookup ads.example.com 127.0.0.1` (or `nslookup -port=5353 ...` when you use another port).
  The *Check* box next to the buttons tells you what the filter would do with a domain, without sending a query.
- **Lists**: hosts files, plain domain lists and Adblock-style `||domain^` rules are understood. A listed domain also blocks its subdomains. Your *Always allow* list wins over everything.
  Single labels (a bare `com`), IP addresses and `localhost`-style entries are never blocked.
- **Blocked names** get `0.0.0.0` / `::` (default; programs fail at once) or "does not exist" (NXDOMAIN). Other record types (HTTPS and so on) get an empty answer.
- **Aliases**: a harmless-looking name that is only a CNAME alias for a blocked name is blocked too (switchable).
- **Browsers**: Firefox's "use-application-dns.net" check is answered with "does not exist", which tells Firefox to keep using this DNS server instead of its own DNS-over-HTTPS.
  Chrome/Edge have a "Secure DNS" setting that can bypass any local DNS; set it to your system DNS if you want it filtered.
- **Query log + statistics**: the last 5000 queries, totals, top blocked / queried domains and clients. *Always allow/block selected* turns a log line into a rule, effective at once.
- **Using it on this PC (manual for now)**: set the DNS server of your network adapter to `127.0.0.1` and keep your old DNS server as the *second* one.
  If SpectraNetworkManager is not running, Windows falls back to the second server after a short delay, so your internet keeps working. (Step 3b automates this, with a one-click restore.)
- **Using it for your whole home network**: set the listen address to `0.0.0.0`, press *Allow local network* (Windows Firewall rules for TCP/UDP on the DNS port, only from your local
  subnet and only on Private/Domain networks), then set your router's DNS server (or a device's) to this PC's IP address. The PC has to be on for that to work.
- **Strict mode**: SpectraNetworkManager itself is always allowed, so its upstream queries and list downloads keep working.
- **Headless**: `SpectraNetworkManager.Spike --dns` runs the same server in a console (options `--port`, `--listen`, `--upstream IP[:port]`, `--block a.com,b.com`, `--update`), also on Linux.
- Not in this step: DNS-over-HTTPS/TLS upstreams, DNSSEC validation (answers are passed through unvalidated), a persistent query history, per-client rules, a DHCP server.

## Strict mode (block by default) - opt-in
Strict mode switches Windows Firewall's default for *outgoing* connections to BLOCK on all profiles. Only programs with an allow rule can connect out:
your own Allow decisions, verified programs from publishers you trust, and a short list of Windows basics (the Windows kernel "System", `svchost.exe`,
`lsass.exe`, the Windows Defender services and SpectraNetworkManager itself). Windows' built-in Core Networking rules (DHCP, DNS, IPv6) stay in place.
Incoming connections are not changed (Windows already blocks them by default).

**Safety net**
- Before anything changes, the previous firewall defaults and a "pending" marker are saved to `%LocalAppData%\SpectraNetworkManager\strict-mode.json`.
- After switching on you have **60 seconds to confirm** that your network works ("Keep strict mode"). A connection check runs automatically (it fetches Microsoft's
  tiny connect-test page, the same one Windows uses). Pressing Enter, closing the window or letting the time run out all switch strict mode **off** again.
- If SpectraNetworkManager crashes or is closed before you confirm, strict mode is switched off at the next start (as Administrator).
- If a basic rule cannot be created, everything is rolled back and strict mode is not switched on.
- **PANIC** (Programs and Rules views): switches strict mode off first, then removes every firewall rule SpectraNetworkManager created.
- Manual way out, in an administrator command prompt: `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`

**How it works day to day**
- When enabling you can allow all programs that are online right now (recommended) so nothing you use stops at once.
- A program without permission is blocked. SpectraNetworkManager reads the block from the Security log (needs auditing, see below) and shows it in the Ask bar:
  **Allow** creates the allow rule (the program has to retry), **Later** leaves it blocked, **Block...** adds an explicit block.
- Programs with a decision "Allowed" or from a trusted publisher get their allow rule automatically when they are first blocked.
- Allow rules are per exe path: a program that updates into a new folder is asked about again unless its publisher is trusted.
- Microsoft Store apps and some Windows components may behave differently. If something stops working, look in the Ask bar and the events list.
- Turning strict mode off removes the allow rules it created (it restores the defaults it saw before, so a PC that already blocked outgoing traffic keeps doing so).

## Signatures and trust
- **SIGNER** is now *verified* by Windows' own Authenticode check (it understands embedded signatures and the catalog signatures most system files use),
  run in the background in small batches and remembered in `%LocalAppData%\SpectraNetworkManager\signature-cache.json` (re-checked when the file changes or after 14 days).
  Certificate revocation is not queried (no network calls).
  - `✔ Publisher` = valid signature. `(Windows)` = signed as part of Windows itself.
  - `not signed` = nobody vouches for it (normal for small tools and your own builds).
  - `✘ untrusted signature` / `✘ SIGNATURE BROKEN` = signed, but the certificate is not trusted, or the file was changed after signing. These raise a WARNING in the events list and in the Ask bar.
  - `checking...` = result not in yet; `unknown` = the check itself did not work.
- **Trust publisher** (Ask bar, Programs view): stop asking about programs with a *verified* signature from that publisher. Your own Block decisions always win.
  Manage the list under **Rules > Trusted publishers**. Trust only publishers you really mean to trust: it covers everything they sign.
- **Protected** (cannot be blocked from here): everything under the Windows folder, Windows Defender's folders, and any file verified as signed by Windows itself. They are also never asked about.
- Ask mode waits for the signature result (up to 20 s) before asking, so trusted or Windows programs do not interrupt you.

## Notes on the other columns
- **HOST**: reverse-DNS name of the remote IP. These lookups are DNS queries sent to your DNS server; untick *Resolve host names* to stop them.
- **Programs view / Internet peers**: distinct remote addresses outside your machine and LAN. Loopback traffic (program talking to itself) does not count.

## Firewall blocks (one-time setup)
Windows only records blocked connections if auditing is on. The Strict mode tab has a button for it, or from an elevated prompt (these use the
subcategory GUIDs, so they work on every Windows language; the English names such as "Filtering Platform Connection" are translated on other languages):
```
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /failure:enable
auditpol /set /subcategory:"{0CCE9225-69AE-11D9-BED3-505054503030}" /failure:enable
```
The first one (blocked connections) is what SpectraNetworkManager needs; the second (individual dropped packets) is only for `--packets`.
Blocked attempts are written to the Security log, so a program that retries all the time makes the log busier.

## Roadmap
0. Spike: connections + owning process - done
1a. Live monitor window, Programs view, host names, signer, firewall block view - done
1b. Engine as a Windows service + local API, per-process bandwidth (ETW), SQLite history (after Phase 2)
2a. Learning mode, per-program allow/block via Windows Firewall rules, panic button - done
2b. Ask mode, Rules view, block direction - done
2c-1. Verified signatures, trusted publishers, wider protection - done
2c-2. Rules with protocol, ports and addresses - done
2c-3. Strict mode: block by default with a safety net - done (tested)
2c-4. Native WFP filters + direct block events (no audit policy needed) - postponed: it needs hand-written native structs that cannot be verified without a Windows test machine
3a. DNS sinkhole: resolver, block lists, cache, query log, LAN permission - **you are here**
3b. One-click system DNS switch (with restore), per-adapter backup
3c. DoH/DoT upstreams, persistent query history, per-client rules
4. Polish: signature trust, profiles, installer, code signing
5. Remote/LAN: web dashboard, multi-machine view

## Safety rules for the firewall phases
- Develop and test blocking in a Windows VM with snapshots.
- Learning mode by default, an allowlist for DHCP/DNS/Windows Update/time sync, and a panic button.
