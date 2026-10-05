---
applyTo: "src/MasterSecurityReviewLauncher/**"
---

For launcher/embedded-audit changes:
- preserve elevation and degraded/non-admin handling;
- preserve explicit privacy-mode selection and redaction behavior;
- treat temporary diagnostic/report artifacts as security-sensitive;
- do not add hidden network telemetry or automatic upload behavior;
- preserve explicit confirmation before any mutating/hardening action.
