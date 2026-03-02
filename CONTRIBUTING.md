# Contributing to mnemom

Thank you for your interest in contributing. This guide covers conventions used across all repositories in the mnemom organization.

## Branch Naming

Use a prefix that describes the type of change:

- `feat/` — New features
- `fix/` — Bug fixes
- `chore/` — Maintenance, dependencies, CI changes
- `docs/` — Documentation only

Example: `feat/add-webhook-support`, `fix/auth-token-refresh`

## Pull Request Requirements

- **CI must pass** before a PR can be merged
- **Descriptive title** summarizing the change
- **Link related issues** in the PR description when applicable
- All repos require PR review — direct pushes to `main` are not allowed

## Commit Style

We prefer [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add user authentication endpoint
fix: resolve race condition in queue processing
chore: update dependencies
docs: add API usage examples
```

## Branch Protection

All repositories enforce branch protection on `main`:

- Pull request required for all changes
- No direct pushes to `main`
- CI checks must pass before merge

## Code of Conduct

Be respectful and constructive in all interactions. We are building together.
