# Master Security Review — Copilot repository instructions

Read `AGENTS.md`, `PROJECT_STATUS.json`, `README.md`, `docs/ARCHITECTURE.md`, and `docs/COMPILE.md` before editing.

Scope:
- Windows first-pass security audit utility;
- C# WinForms launcher targeting .NET Framework 4.8;
- embedded PowerShell audit implementation.

Safety rules:
- preserve audit/review positioning; do not imply antivirus/EDR/forensic completeness;
- preserve privacy/redaction semantics;
- do not introduce silent remediation or destructive behavior;
- optional hardening/removal actions must remain explicit and user-confirmed;
- never replace or rebuild the published v1.0.0 artifact when changing current source.

Build/release:
- canonical build target is Release|AnyCPU;
- GitHub Actions same-runner deterministic comparison is the merge gate;
- do not claim cross-toolchain bit-for-bit reproducibility from that CI check;
- new releases require a new version/tag and new hashes.

Changes should remain small, reviewable, and Windows-compatible.
