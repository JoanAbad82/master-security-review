# Contributing to Master Security Review

Thanks for your interest in contributing.

This project is open to contributions, but it is intentionally managed with a **controlled scope**. The goal is to keep V1 useful, understandable, and maintainable.

## Before you contribute

Please keep these project principles in mind:

- clarity over cleverness;
- practical usefulness over feature bloat;
- security and trust over unnecessary complexity;
- maintainable scope over roadmap drift.

## License and contribution terms

No separate CLA is required for V1.

By submitting a contribution, you agree that your contribution will be licensed under the same license as this project, unless explicitly stated otherwise.

## Development setup status

Public V1 packaging and build details are still being finalized.

Before the first public release is published, the repository should document:

- supported operating system and runtime requirements;
- local development setup;
- local execution path for testing;
- packaging and build steps;
- known limitations that affect contributors.

Until those instructions are finalized, please open an issue before spending significant time on larger code or packaging changes.

## What is welcome

Contributions are especially welcome in these areas:

- reproducible bug reports;
- documentation improvements;
- report clarity improvements;
- release engineering improvements;
- focused fixes that clearly improve reliability or safety.

## What may be declined

The maintainers may decline contributions that:

- significantly expand scope without prior discussion;
- add complexity without a strong practical gain;
- change the positioning of the project into a broader security suite;
- introduce behavior that weakens reviewability or safer sharing of reports;
- conflict with the current V1 freeze or release goals.

## Issue guidelines

When opening an issue, please include:

- what you expected to happen;
- what actually happened;
- the environment you tested in;
- clear reproduction steps if possible;
- screenshots or logs only if they do not expose sensitive data.

### Example of a good issue

> On Windows 11, the network-related review section reports no active
> connections even when common user applications are visibly using the
> network. Expected: the report should reflect active network context instead
> of showing an empty result.

### Example of a poor issue

> It doesn't work. Fix it.

## Pull request guidelines

If you want to open a pull request:

1. Open an issue first for anything that is more than a very small fix.
2. Keep the change narrow.
3. Explain the practical value of the change.
4. Avoid unrelated refactors.
5. Update documentation when behavior changes.
6. Be careful not to expose sensitive sample data in tests, screenshots, or
   fixtures.

## Code style expectations

Keep contributions easy to review and consistent with the existing codebase.

Minimum expectations:

- use 4 spaces for indentation unless the existing file clearly uses another
  style consistently;
- avoid unnecessary formatting churn;
- keep comments for non-obvious logic;
- do not add credentials, tokens, personal identifiers, or machine-specific
  paths to examples, fixtures, screenshots, or test data;
- follow any repository linters or analyzers once they are published in the
  public repo.

## Response expectations

Issues and pull requests should normally receive an initial maintainer response within 7 days. Complex changes may take longer to assess. If there is no response after 14 days, a polite follow-up is acceptable.

## Coding and review expectations

Pull requests should aim to be:

- easy to review;
- limited in scope;
- consistent with the existing structure;
- aligned with the project's security and trust goals.

## Security reporting

Do **not** open a public issue for a suspected security vulnerability. Follow the instructions in [SECURITY.md](SECURITY.md).

## Recognition

Contributors may be recognized in project history, release notes, or other project materials where appropriate.

## Final note

A contribution being technically correct does not automatically mean it fits the release scope or product direction. The maintainers reserve the right to decide what is accepted into the project.