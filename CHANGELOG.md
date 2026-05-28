# Changelog

All notable changes to `zylos-infra-security-starter` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `ActorChainIntegrationIT` updated for the model: real-token coverage
  of public access, non-sensitive authenticated-only permit, standard
  default permit, chain-sensitive empty-chain deny, and strict no-match deny.

### Notes

- ADR 0006 documents the real-`act` coverage boundary: the positive
  chain-match path is covered across the keycloak-extensions mapper IT, the
  starter's unit tests, and (for full wiring) the deferred Sub-phase
  service test — not in the starter's own integration tests, which run against
  vanilla Keycloak.
- **Sub-phase (zylos-infra-security-starter) is now complete.**
