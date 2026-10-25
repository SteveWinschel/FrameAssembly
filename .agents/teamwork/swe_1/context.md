# Context for SWE Light (`teamwork_preview_swe`)

## Original Request
See `/home/steve/frameassembly/.agents/teamwork/ORIGINAL_REQUEST.md` (section `## 2026-10-25T13:21:36Z`).

## Mission
Create a cross-platform `install.sh` bootstrap script for FrameAssembly (`frameassembly`) that installs missing system prerequisites (`curl` and a C linker), installs Rust/Cargo via `rustup`, and installs `frameassembly` via `cargo`, along with updating `README.md` and repository metadata files.

## Working Directory
`/home/steve/frameassembly/.agents/teamwork/swe_1`

## Repository Root
`/home/steve/frameassembly`

## Hard Constraints
- Do NOT modify any file inside `/home/steve/frameassembly/src/`.
- Do NOT bump the `version` field in `/home/steve/frameassembly/Cargo.toml`.
- Do NOT run `git commit`, `git push`, or `git tag`.
- Ensure `README.md` remains strictly `< 50,000` bytes (`wc -c < README.md`) with zero NUL (`0x00`) bytes.
- Ensure `*.sh text eol=lf` is added to `.gitattributes`.
- Remove the stray 0-byte `=` file in `/home/steve/frameassembly/`.
- Run and verify all acceptance criteria including `sh -n install.sh`, `bash -n install.sh`, `./install.sh --help`, and `cargo test`.
