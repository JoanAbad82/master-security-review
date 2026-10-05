# AGENTS.md

## Purpose

Master Security Review is a Windows first-pass security audit utility. The public launcher is a C# WinForms application targeting .NET Framework 4.8 and executes an embedded PowerShell audit script to produce a structured local report.

`PROJECT_STATUS.json` provides a compact machine-readable snapshot of release state, architecture, validation and interaction boundaries.

## Canonical sources

1. `README.md` — public scope, release positioning, limitations, and integrity information.
2. `docs/ARCHITECTURE.md` — compact execution/data-flow model.
3. `src/MasterSecurityReviewLauncher/` — launcher implementation and embedded audit asset.
4. `docs/COMPILE.md` — supported source-build workflow.
5. `.github/workflows/build.yml` — CI build/determinism check for the current toolchain.

## Build validation

Use the repository's documented Release|AnyCPU build path. GitHub Actions must remain green. The CI check establishes buildability and same-runner deterministic output; it is not proof of cross-toolchain bit-for-bit reproducibility.

## Security boundaries

- This tool is an audit/review aid, not antivirus, EDR, incident response, or a forensic suite.
- Findings require human review; both false positives and false negatives are possible.
- Preserve privacy modes and redaction semantics when changing report output.
- Optional destructive/hardening actions in the embedded script must remain explicit, user-confirmed, and disabled by default unless a separately reviewed change says otherwise.
- Do not add silent remediation behavior to the normal audit path.

## Release boundary

The published `v1.0.0` artifact is immutable historical release evidence. Do not replace/rebuild that asset when changing current source or CI. A new release must use a new version/tag and document its own hashes/toolchain.
