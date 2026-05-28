# Changelog

All notable changes to `zylos-infra-security-starter` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Authorization model.** Actor-chain matching is now opt-in per
  endpoint via `chainSensitive: true`. Non-sensitive endpoints (the default)
  authorize on a valid authenticated token without chain matching.
- `ChainDefaults.standard()` (permit-authenticated-by-default) replaces
  `strict()` as the substituted default when `actor-chains.yaml` omits
  `defaults:`. `strict()` remains available for allowlist semantics.
- `PathCheckResult` refactored to a sealed interface with three cases
  (`Immediate`, `AuthenticatedOnly`, `ChainEvaluation`).

### Added

- `EndpointChainRule.chainSensitive` flag (default false) with a 3-arg
  convenience constructor preserving existing call sites.
- `ActorChainEvaluator.evaluateAuthenticatedOnly` for non-chain-sensitive
  authorization; new permit reason `authenticated`.
- `ActorChainEvaluatorTest` covering the three-way path-check outcomes.

### Notes

- ADR 0003 gains a refinement section documenting the rationale,
  sensitivity taxonomy, and the default change.
