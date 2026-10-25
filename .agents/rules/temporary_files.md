---
trigger: always_on
description: "Workspace temp/ directory and RAII cleanup guard hygiene for scratch packet captures."
---

# Temporary Files Rule

- Always save temporary workspace files in the `temp/` directory at the root of the workspace (or use RAII cleanup guards in `std::env::temp_dir()` for automated tests).
- Ensure that the `temp/` directory and scratch capture outputs (`*.pcap`, `*.pcapng`) are listed in `.gitignore` so temporary artifacts are never accidentally committed.
