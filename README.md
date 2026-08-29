<p align="center">
  <h1 align="center">👻 GhostLink</h1>
  <p align="center">
    <strong>Ultra-lightweight, high-performance DPI bypass & censorship resilience tool for macOS & Windows</strong><br>
    Built with Rust & Tauri v2
  </p>
</p>

<p align="center">
  <a href="#-download--quickstart-for-macos">🍎 Download for macOS</a> •
  <a href="#-download--quickstart-for-windows">🪟 Download for Windows</a> •
  <a href="#-features--architecture">✨ Features & Architecture</a> •
  <a href="#-discord-voice--udp-bypass-comparison">🎙️ Discord Voice</a>
</p>

---

## 📖 Overview

**GhostLink** is a modern, transparent DPI (Deep Packet Inspection) bypass application designed to restore direct, line-speed access to services like **YouTube (1080p/4K), Discord (including Voice & Video calls)**, and other restricted web platforms without routing your traffic through third-party VPN servers.

---

## 📥 Downloads

### 🍎 Download for macOS
> **Supported:** macOS 12 (Monterey), macOS 13 (Ventura), macOS 14 (Sonoma), macOS 15 (Sequoia)  
> **Architectures:** Apple Silicon (M1/M2/M3/M4/M5) & Intel (x86_64) Universal

- **GhostLink Menu Bar App (.dmg / .zip):** [GhostLink-macOS-Universal.zip](https://github.com/dev-aaw/GhostLink/releases/latest)
- **GhostLink CLI + Daemon (.tar.gz):** [ghostlink-macos-cli.tar.gz](https://github.com/dev-aaw/GhostLink/releases/latest)

```bash
# Quick install via Terminal on macOS:
git clone https://github.com/dev-aaw/GhostLink.git
cd GhostLink/src-tauri
cargo build --release --bin ghostlink_cli --bin ghostlink_daemon --bin ghostlink_menubar
```

---

### 🪟 Download for Windows
> **Supported:** Windows 10 (1809+) & Windows 11 (21H2+) 64-bit  
> **Driver:** WinDivert 2.2 / Flowseal 1.9.9c (SHA-256 verified)

- **GhostLink Windows Installer (.exe / .zip):** [GhostLink-Windows-x64.zip](https://github.com/dev-aaw/GhostLink/releases/latest)
- **GhostLink CLI + Service (.zip):** [ghostlink-windows-cli.zip](https://github.com/dev-aaw/GhostLink/releases/latest)

```powershell
# Quick install via PowerShell on Windows (Run as Administrator):
git clone https://github.com/dev-aaw/GhostLink.git
cd GhostLink\src-tauri
cargo build --release --bin ghostlink_cli --bin ghostlink_daemon
```

---

## 🎙️ Discord Voice & UDP Bypass Comparison

| Feature | 🪟 Windows (WinDivert Engine) | 🍎 macOS (tpws + Smart Router) |
| :--- | :--- | :--- |
| **YouTube (4K / 60 FPS)** | ✅ Native DPI Desync (Direct TCP) | ✅ Native DPI Desync (Direct SOCKS) |
| **Discord Web & App** | ✅ Native DPI Desync (Direct TCP) | ✅ Native DPI Desync (Direct SOCKS) |
| **Discord Media / Images** | ✅ Native TCP Port Desync (2053-8443) | ✅ Native TCP Port Desync |
| **Discord Voice Channels (WebRTC)** | ✅ **Native UDP STUN Desync (0 VPN needed!)** | 🛡️ Split WireGuard Fallback / Smart Router |
| **System Proxy Required?** | ❌ **NO (Transparent Kernel Driver)** | ✅ Auto-managed by SOCKS helper |
| **Admin Prompt Frequency** | ⚡ **Once** (via Task Scheduler / Service) | ⚡ **Once** (via LaunchDaemon) |

> 💡 **Why does Discord Voice work without a VPN on Windows?**  
> On Windows, GhostLink utilizes `winws.exe` + the `WinDivert` kernel network driver. WinDivert filters both L3/L4 TCP **and** UDP packets at the driver level. GhostLink's **8-rule architecture** actively desynchronizes UDP ports `19294-19344` and `50000-50100` using fake STUN packets (`--filter-l7=discord,stun --dpi-desync=fake`), enabling **100% native voice and video calls** without requiring an external VPN tunnel!

---

## ✨ Features & Architecture

```
GhostLink/
├── src-tauri/
│   ├── Cargo.toml                # Unified Rust dependencies (platform-isolated)
│   └── src/
│       ├── lib.rs                # Core engine export library
│       ├── bin/
│       │   ├── ghostlink_cli.rs    # Cross-platform CLI benchmark & control tool
│       │   ├── ghostlink_daemon.rs # Privileged background helper daemon (Unix socket / Windows Loopback)
│       │   └── ghostlink_menubar.rs# macOS native AppKit status bar application
│       └── engine/
│           ├── types.rs          # Platform, Strategy & Probe models
│           ├── payloads.rs       # In-memory QUIC, TLS SNI & STUN packet generators
│           ├── binary_manager.rs # Verified upstream binaries with SHA-256 validation
│           ├── strategies.rs     # macOS (tpws) & Windows Flowseal 8-rule strategies
│           ├── probes.rs         # Direct HTTP/TLS & CDN verification probes
│           ├── process.rs        # Safe process management (no shell injection)
│           ├── ipc.rs            # Line-based JSON IPC client & server
│           ├── service.rs        # macOS LaunchDaemon & Windows Task Scheduler manager
│           ├── smart_router.rs   # Dynamic IP route manager
│           ├── wireguard.rs      # WireGuard tunnel controller
│           ├── autostart.rs      # macOS LaunchAgent & Windows Run registry manager
│           └── notifications.rs  # macOS osascript & Windows Toast notifications
```

---

## 🚀 Usage Guide

### 1. One-Time Elevated Service Installation
GhostLink includes a background helper daemon that runs with elevated privileges so you never see repeated UAC or password prompts:

```bash
# macOS (creates /Library/LaunchDaemons/com.ghostlink.helper.plist):
sudo ./ghostlink_cli service install

# Windows (Run PowerShell as Administrator, registers Task Scheduler job):
.\ghostlink_cli.exe service install
```

Verify service status:
```bash
ghostlink_cli service status
```

---

### 2. Auto-Tune ISP Benchmark
Automatically test all desync strategies against live YouTube, Discord, and target endpoints to find the optimal strategy for your specific ISP:

```bash
ghostlink_cli autotune
```

Example Output:
```
🎯 [AUTOTUNE BENCHMARK] Testing all strategies for Windows...
   • [1/6] Windows ALT9 (Recommended First) -> PASS (142ms)
   • [2/6] Windows ALT11 -> PASS (158ms)
   • [3/6] Windows general -> PASS (176ms)
   • [4/6] Windows ALT3 -> PASS (190ms)
   • [5/6] Windows ALT10 -> PASS (210ms)
   • [6/6] Windows Simple Fake -> PASS (135ms)

🏆 BEST STRATEGY FOUND: Windows Simple Fake (Latency: 135ms)
```

---

### 3. Start GhostLink Engine

```bash
# Start with the recommended strategy:
ghostlink_cli start -s win-alt9

# Or start via the background daemon:
ghostlink_cli service start -s win-alt9
```

---

### 4. Test Connectivity (Probe Test)

```bash
ghostlink_cli test -s 1
```

---

### 5. Stop GhostLink Engine

```bash
ghostlink_cli stop
```

---

## 🔒 Security & Privacy Guarantees

- **No Remote Telemetry:** GhostLink never collects or transmits user activity or browsing logs.
- **SHA-256 Binary Verification:** All bundled/downloaded low-level binaries (`winws.exe`, `WinDivert.dll`, `WinDivert64.sys`, `tpws`) are verified against immutable cryptographic SHA-256 hashes prior to extraction and execution.
- **Safe Subprocess Execution:** All system commands use direct argument vectors with strict validation (preventing shell injection and argument injection vulnerabilities).
- **Credentials Protection:** WireGuard private keys and configuration details are strictly ignored in `.gitignore` and never committed or transmitted.

---

## 📜 License
This project is licensed under the [MIT License](LICENSE).
