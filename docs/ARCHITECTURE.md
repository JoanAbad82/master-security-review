# Architecture

## System role

Master Security Review is a local Windows audit/reporting tool. It packages a C# launcher and an embedded PowerShell audit implementation into a small Windows-facing workflow.

## Execution flow

```text
User
  -> WinForms launcher (`Program.cs`)
       -> elevation check / administrator relaunch when needed
       -> privacy-mode selection
       -> temporary run directory
       -> decode + wrap embedded PowerShell asset (`EmbeddedAssets.cs`)
       -> execute Windows PowerShell
            -> collect audit signals
            -> apply privacy/redaction policy
            -> write structured text report
       -> parse report path / diagnostics
       -> present completion or failure to user
```

## Inputs

- Local Windows system state.
- User-selected privacy mode/configuration.
- Optional user confirmations for explicitly destructive/hardening actions when such options are enabled.

## Audit surface

The embedded audit script includes checks around system/security context such as:

- processes and executable paths;
- services and drivers;
- scheduled/persistence-related context;
- firewall/network-related context;
- WMI subscription/consumer context;
- browser extensions and selected browser permission/session indicators;
- Windows Defender detection/status information;
- file trust/signature/hash context where available.

The exact current checks are defined by the embedded PowerShell source encoded in `EmbeddedAssets.cs`; this document is an orientation layer, not a replacement for source.

## Privilege boundary

The launcher contains an administrator/elevation path so the normal UI can request broader Windows visibility. The embedded script also contains degraded/non-admin handling because some checks may be unavailable when it is executed outside the elevated launcher path.

## Privacy/report boundary

The report pipeline supports privacy profiles including full/internal, review/chat-safe, and custom behavior. Depending on the selected profile, sensitive fields such as paths, command lines, identifiers, network values, and hashes may be included, masked, redacted, or hidden.

A generated report is still security-sensitive. Users must review it before sharing.

## Temporary execution and diagnostics

The launcher creates a temporary run directory, writes the wrapped PowerShell script, executes it, captures stdout/stderr, extracts the report path, and can retain diagnostic paths/logs on failure. This means temporary/diagnostic artifacts can contain security-relevant information and should be treated accordingly.

## Mutation boundary

The default positioning is audit/review. The embedded script contains optional hardening/removal capabilities, but these are controlled by explicit options and confirmation logic. They are not equivalent to the normal information-gathering path and must not become implicit side effects.

## Build/release boundary

- Project type: legacy non-SDK C# / WinForms.
- Target: .NET Framework 4.8.
- Canonical CI configuration: `Release|AnyCPU` on Windows.
- CI builds twice on the same runner/toolchain and compares SHA-256 hashes.
- Same-runner determinism does not guarantee cross-version/cross-machine reproducibility.
- Published release artifacts and their SHA-256 values are version-specific evidence.

## Known limitations

- Windows-specific.
- Not comprehensive malware detection or forensic analysis.
- Can miss malicious activity and can flag benign activity.
- Availability/quality of individual checks depends on Windows version, privileges, installed components, and PowerShell/cmdlet availability.
- Privacy redaction reduces exposure but cannot guarantee that every report is safe to publish without review.
- The current published executable is unsigned; verify official release hashes before use.
