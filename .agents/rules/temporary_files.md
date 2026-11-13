---
trigger: always_on
description: "Workspace temp/ directory hygiene and thread-safe RAII cleanup guards for scratch packet captures."
---

# Temporary Files & Scratch Capture Rule

- **Workspace Scratch Files**: Save manual or ad-hoc scratch files strictly inside the root `temp/` directory—never scatter scratch `.frasm`, `.pcap`, `.pcapng`, or `.vsix` files in the repository root.
- **Parallel-Safe Test Captures**: In automated Rust tests (`tests/**/*.rs`), generate unique paths inside `std::env::temp_dir()` combining `std::process::id()` and a monotonic `AtomicU64` counter wrapped in an RAII `Drop` cleanup guard so parallel `cargo test` threads never collide or leak `.pcap` artifacts on assertion failure.
- **Ignore & Exclude Hygiene**: Keep `temp/`, `*.pcap`, and `*.pcapng` listed in both `.gitignore` and `Cargo.toml` `package.exclude`.