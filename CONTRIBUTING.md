# Contributing to zylos-infra-security-starter

## Branching

- Trunk-based development; `main` is always deployable.
- Short-lived feature branches: `feat/`, `fix/`, `chore/`, `docs/`, `refactor/`, `test/`, `ci/`.
- Squash-merge PRs to `main` only. No force-push, no direct push to `main`.

## Commits

[Conventional Commits 1.0](https://www.conventionalcommits.org/en/v1.0.0/) enforced via commitlint in CI:

```
feat(jwt): add forced JWKS refresh on unknown kid
fix(opa): correctly propagate timeout from properties
test(actor): add chain-depth boundary tests
```

All commits must be signed with an SSH or GPG key registered to your GitHub account.

## Pull Requests

- Use the PR template.
- Include tests covering new code paths.
- Maintain ≥85% line coverage (gate enforced by JaCoCo).
- Spotless / Palantir Java Format passes (`./mvnw spotless:check`).
- ArchUnit tests pass (`./mvnw test -Dtest='*Architecture*'`).
- One approving review required.

## Local Build

```bash
./mvnw verify       # full build, tests, coverage gate
./mvnw test         # unit tests only
./mvnw spotless:apply  # auto-fix formatting
```

## Code Style

- **No Lombok.** Java 25 records, sealed types, and explicit accessors only.
- **JSpecify null-safety** on public API.
- **Palantir Java Format** via Spotless (enforced).
- 120-character line limit, 4-space indentation for Java.

## Release Process

Releases are tagged via GitHub Releases. The `publish.yaml` workflow builds and publishes to GitHub Packages on every published release.
