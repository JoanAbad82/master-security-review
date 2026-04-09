# Security Policy

Thanks for helping keep Master Security Review safe and trustworthy.

## Supported versions

During the initial public stage, only the latest published **V1.x** release should be assumed to be actively supported for security reporting and fixes unless the release notes explicitly state otherwise.

| Version line | Supported |
| --- | --- |
| Latest V1.x release | Yes |
| Older V1.x releases | Best effort, no guarantee |
| Pre-release or unpublished preparation files | No |

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, report them privately to:

- **Security contact:** `security@openutilitylab.com`
- **Preferred subject line:** `Master Security Review security report`

Please include, where possible:

- a clear description of the issue;
- the affected version;
- reproduction steps;
- impact assessment;
- any proof of concept that is strictly necessary to understand the issue.

If you are unsure whether something is a vulnerability or a normal bug, prefer private reporting first.

## Response expectations

The project aims to provide:

- acknowledgment within 72 hours;
- an initial assessment within 7 days;
- follow-up timing based on severity and complexity, communicated when appropriate.

## Encrypted reporting

PGP support is not yet defined in this V1 preparation pack. Until a public key is explicitly published by the project, plain email should be assumed to be the available reporting channel.

## Bug bounty

This project currently does **not** offer a bug bounty program. Vulnerability reports are appreciated as good-faith contributions to software safety.

## What to report

Please report issues such as:

- unintended exposure of sensitive data in reports or logs;
- unsafe default behavior;
- packaging or distribution integrity issues;
- vulnerabilities introduced by project code or official release artifacts;
- dependency vulnerabilities that materially affect official builds or releases.

## Disclosure

Please allow reasonable time for investigation and remediation before public disclosure.

## Release trust notes

Official releases should clearly state:

- whether binaries are signed;
- how integrity hashes are published;
- any known trust limitations of the packaging model for that release line.

Always verify downloaded releases against the integrity hashes published in the official release notes.

## Scope note

This policy applies to the project code, official release artifacts, and materially relevant dependency vulnerabilities affecting those official artifacts.