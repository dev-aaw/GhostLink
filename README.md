<p align="center">
  <h1 align="center">👻 GhostLink</h1>
  <p align="center">
    <strong>Ultra-lightweight, high-performance DPI bypass & censorship resilience desktop tool for macOS & Windows</strong><br>
    Built with Rust & Tauri v2
  </p>
</p>

---

## 📖 Overview

**GhostLink** is a modern, transparent DPI (Deep Packet Inspection) bypass application designed to restore unthrottled, direct access to services like **YouTube, Discord (including voice & video calls)**, and other restricted web platforms without sending your traffic through a third-party VPN server.

### ✨ Key Principles & Features
- **Zero-VPN / Direct Speed:** Manipulates packet headers locally so you connect directly to target servers at maximum line speed with 0 added proxy latency.
- **Tauri v2 + Rust Architecture:** Uses ~25MB of RAM idle, starts instantly, leaves zero orphan background processes.
- **8-Tier Packet Desync:** Implements verified multi-split, TLS ClientHello SNI spoofing, QUIC initial fragmentation, and Discord STUN UDP desynchronization.
- **Smart Auto-Tune Benchmark:** Automatically tests your ISP against actual YouTube and Discord endpoints to discover and lock in the fastest working strategy.
- **Cross-Platform:** Native support for macOS (Apple Silicon M1-M5 & Intel) and Windows 10/11 x64.
- **100% Clean:** No telemetry, no third-party ads, no bundled VPN promotions.

---

## 🏗️ Architecture

```
ghostlink/
├── src-tauri/
│   ├── Cargo.toml             # Rust dependencies & crate config
│   └── src/
│       ├── lib.rs             # Engine exports
│       ├── bin/
│       │   └── ghostlink_cli.rs # Standalone CLI test & verification harness
│       └── engine/
│           ├── types.rs       # Platform, Strategy & Probe data models
│           ├── payloads.rs    # In-memory QUIC, TLS SNI & STUN packet generators
│           ├── binary_manager.rs # Verified upstream binaries with SHA-256 validation
│           ├── strategies.rs  # macOS (tpws) & Windows (winws 8-rule) strategies
│           ├── probes.rs      # 2-Tier HTTP/TLS & CDN verification probes
│           ├── process.rs     # Low-level process lifecycle & signal controller
│           ├── system_proxy.rs # macOS networksetup proxy & hosts rollback manager
│           └── mod.rs         # High-level UnblockEngine facade
```

---

## 🚀 Quick Start (CLI Engine Test)

### 1. Requirements
- **Rust & Cargo:** Install via [rustup.rs](https://rustup.rs):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

### 2. Run GhostLink CLI
Navigate to `src-tauri`:
```bash
cd src-tauri
```

#### List Available Strategies
```bash
cargo run --bin ghostlink_cli -- list
```

#### Run Baseline Censorship Test
```bash
cargo run --bin ghostlink_cli -- probe-direct
```

#### Auto-Tune: Benchmark & Find Working Strategy for your ISP
```bash
cargo run --bin ghostlink_cli -- autotune
```

#### Start GhostLink Engine
```bash
cargo run --bin ghostlink_cli -- start -s mac-split-midsld
```

---

## 📜 License
This project is licensed under the [MIT License](LICENSE).
