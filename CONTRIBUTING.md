# Contributing to SpectraNetworkManager

Thank you for your interest in contributing to **SpectraNetworkManager**! 

SpectraNetworkManager is a free, privacy-first Windows security tool combining real-time network traffic monitoring, per-application outbound firewall controls, and a high-performance local DNS sinkhole.

We welcome contributions from developers, security researchers, translators, and privacy enthusiasts of all skill levels.

---

## Guiding Principles

Every contribution must align with our core commitments:
1. **100% Free & Open Source:** Licensed under the MIT License. No paywalls, paid tiers, or restricted features.
2. **Zero Telemetry & Zero Data Collection:** All network logs, DNS queries, and firewall states remain strictly local on the user's machine. No phone-home calls, analytics, or tracking scripts will ever be accepted.
3. **Safety & Fail-Safe Design:** Any feature that modifies firewall rules, network adapter settings, or routing must provide an instant rollback mechanism (e.g., 60-second safety timeout, Safe Recovery Mode, and Panic restore).
4. **Reliability & Native Performance:** Low CPU and memory overhead; avoid heavy external runtimes or invasive kernel drivers.

---

## How Can I Contribute?

### 1. Reporting Bugs
- Before submitting an issue, search existing [GitHub Issues](https://github.com/Creator-NL/SpectraNetworkManager/issues) to see if it has already been reported.
- Use the **Bug Report** template.
- Include your Windows version (e.g., Windows 11 23H2), .NET runtime version, reproduction steps, expected vs. observed behavior, and relevant log lines (from `%ProgramData%\SpectraNetworkManager\logs`).

### 2. Suggesting Enhancements & Features
- Open an issue using the **Feature Request** template.
- Clearly explain the problem or workflow you wish to improve, along with potential implementation ideas or UI mockups.

### 3. Testing Web & Interactive Features
- You can preview and test interactive prototypes in your browser at [https://biohazard-corp.nl/spectranetworkmanager.html](https://biohazard-corp.nl/spectranetworkmanager.html).
- Feedback on usability, dark/light theme contrast, and documentation clarity is always appreciated.

### 4. Contributing Code

#### Development Prerequisites
- **Operating System:** Windows 10 (Build 19041+) or Windows 11 (x64 / ARM64).
- **IDE:** Visual Studio 2022 (v17.8 or newer) with *.NET desktop development* workload, or JetBrains Rider / VS Code with C# Dev Kit.
- **SDK:** Microsoft .NET 8.0 SDK (x64).
- **Installer (optional):** Inno Setup 6 (if building the setup installer executable).

#### Building the Project
1. Clone the repository:
   ```bash
   git clone https://github.com/Creator-NL/SpectraNetworkManager.git
   cd SpectraNetworkManager
   ```
2. Build the solution:
   ```bash
   dotnet build SpectraNetworkManager.sln -c Release
   ```
3. Run the automated test suite:
   ```bash
   dotnet test SpectraNetworkManager.sln -c Release
   ```
   *All unit and platform tests must pass before submitting code.*

#### Running Elevated
SpectraNetworkManager interacts with Windows Filtering Platform (WFP), ETW kernel trace sessions, and Windows Firewall rules. For full visibility during development:
- Run Visual Studio or your compiled executable **as Administrator**.

---

## Project Architecture

The codebase is cleanly divided into modular layers:

- **`SpectraNetworkManager.Core`**: Platform-independent business logic, DNS sinkhole engine, rule planners, address/port sets, IPC protocols, and models. Zero UI dependencies.
- **`SpectraNetworkManager.Platform.Windows`**: Windows-specific low-level integrations: IP Helper API (`GetExtendedTcpTable`), ETW bandwidth tracing, native Authenticode verification (`WinVerifyTrust`, `CryptCATAdmin`), and Windows Firewall enforcer.
- **`SpectraNetworkManager.Engine`**: Background Windows Service running as `LocalSystem` for continuous DNS sinkholing, WFP drop monitoring, and rule enforcement.
- **`SpectraNetworkManager.App`**: WPF user interface (.NET 8 Windows desktop client) featuring dark/neon cyber aesthetic, MVVM design, and real-time data binding.
- **`installer/`**: Inno Setup packaging and automated build script (`build-package.ps1`).

---

## Pull Request Guidelines

1. **Create a Feature Branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. **Commit Conventions:**
   - Write clear, meaningful commit messages describing *what* and *why*.
   - Keep commits focused and atomic.
3. **Verify Tests:**
   - Ensure all existing tests pass (`dotnet test SpectraNetworkManager.sln -c Release`).
   - If adding new logic (parsers, filters, calculations), add corresponding unit tests in `tests/SpectraNetworkManager.Tests`.
4. **Submit Your PR:**
   - Open a PR against the `main` branch.
   - Fill out the provided Pull Request template.
   - Maintainers will review your PR and provide constructive feedback.

---

## Community & Contact

- **GitHub Issues:** [https://github.com/Creator-NL/SpectraNetworkManager/issues](https://github.com/Creator-NL/SpectraNetworkManager/issues)
- **Official Website:** [https://biohazard-corp.nl](https://biohazard-corp.nl)
- **Direct Contact:** `contact@biohazard-corp.nl`
