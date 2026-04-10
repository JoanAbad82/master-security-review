# Master Security Review
### Quick Windows Audit Tool

Master Security Review is an open source Windows audit utility designed to help users run a fast, practical first-pass security review and generate a report that is useful, shareable, and easier to review safely.

It is meant to **complement** your antivirus and your own judgment. It is **not** an antivirus, EDR, forensic suite, or a guarantee that a system is clean.

## Why this project exists

The goal of V1 is simple:

- save time during an initial Windows security review;
- present findings in a more structured and reviewable way;
- reduce unnecessary exposure of sensitive details when a report needs to be shared;
- provide a transparent, maintainable open source foundation for future utilities.

## Current V1 positioning

**Master Security Review** should be understood as a **quick Windows audit tool**.

It is intentionally positioned as:

- practical;
- transparent;
- lightweight in scope;
- useful for individual users and light technical review;
- complementary to Microsoft Defender or another antivirus.

It is intentionally **not** positioned as:

- a replacement for professional incident response;
- a managed enterprise security platform;
- a real-time monitoring product;
- a full forensic investigation toolkit.

## Releases

Current V1 release artifact: `MasterSecurityReview-v1.0.0.zip`

Contents:

- `MasterSecurityReviewLauncher.exe`
- `MasterSecurityReviewLauncher.exe.config`

SHA256: `375389CAA3E0EFAF48CEB14C031027DE800E2556FDBE9B7E06073CD8FFB0CF4A`

The public download path will be added upon GitHub release publication.

Compilation from source is documented in `docs/COMPILE.md`.

## Typical review scope

The exact checks supported by each release are defined by the source code and release notes. In broad terms, V1 is intended to cover practical categories such as:

- selected startup and persistence-related review signals;
- selected scheduled task and autorun review context;
- selected process, service, and execution-path review context;
- selected network-related review context;
- selected Windows security and Defender-related status signals;
- report generation with a stronger focus on reviewability and safer sharing.

## Example output (abridged)

```text
=== MASTER SECURITY REVIEW REPORT ===
Date: YYYY-MM-DD HH:MM:SS

[STARTUP AND PERSISTENCE]
- Example startup entry listed for review

[PROCESS AND EXECUTION CONTEXT]
- Example process entry listed for review

[NETWORK CONTEXT]
- Example network-related entry listed for review

[WINDOWS SECURITY STATUS]
- Example status line shown here
```

## How to read the report

Red flags require investigation. Informational or apparently benign items may still matter depending on context. The report is a review aid, not a final verdict.

## Privacy and report sharing

One of the core design goals of this project is not only to produce a useful report, but to produce a report that is easier to review and safer to share.

Depending on the mode used, reports may reduce unnecessary exposure of sensitive details such as paths, identifiers, or other values that are often not required for external review.

**Important:** a shared report is still a security-related artifact. Always review it before sending it to another person or publishing it anywhere.

## Permissions

The most complete review results may depend on how the tool is executed.

* **Without administrator privileges:** some checks may be limited to the current user context.
* **With administrator privileges (recommended when appropriate):** broader review context may be available, including areas that are not fully visible from a standard user context.

Exact privilege requirements per release should be documented in the release notes or usage instructions.

## Important limitations

* This tool will miss many threats.
* It may flag harmless items as suspicious or noteworthy.
* Findings require human judgment.
* It should not be the sole basis for a security decision.
* It does not replace antivirus scanning, professional incident response, or a full forensic review.

## Integrity verification

Official releases should publish integrity hashes. On Windows, a downloaded file can be checked with a command such as:

```powershell
certutil -hashfile <downloaded-file.exe> SHA256
```

Always compare the resulting hash with the value published in the official release notes.

## System and execution notes

This project targets Windows. Exact runtime and packaging details may evolve during the V1 public release process and will be documented per release.

Before the public release is finalized, the repository should document:

* supported Windows versions;
* packaging model;
* execution requirements;
* whether administrator privileges are recommended or required for specific checks;
* any known limitations.

Compilation from source is documented in docs/COMPILE.md. The current V1 artifact and its SHA256 are documented above. The public download path will be added upon GitHub release publication.

## Project status

V1 is being prepared as:

* a public repository;
* a free official download;
* an MPL-2.0 licensed project;
* a release workflow with verifiable published artifacts.

## Roadmap philosophy

V1 is intended to be small, useful, and credible.

After the V1 freeze, only the following changes should normally enter the branch for that release line:

* bug fixes;
* security fixes;
* documentation clarity improvements;
* packaging and release improvements.

New audit categories or material scope expansions belong to a later version.

## Contributing

Contributions are welcome, but the project is intentionally maintained with a controlled scope.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

If you believe you have found a vulnerability, please read [SECURITY.md](SECURITY.md) before reporting it publicly.

## Code of Conduct

This project adopts the community rules described in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Funding

If this project saves you time or helps you, consider supporting its maintenance through the funding links shown in the repository.

## License

This project is licensed under the **Mozilla Public License 2.0**. See [LICENSE](LICENSE).
