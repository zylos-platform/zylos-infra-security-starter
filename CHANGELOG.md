# Changelog

All notable changes to `zylos-infra-security-starter` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Actor-chain authorization: `ActChainExtractor`, `ActorChainsLoader`,
  `ActorChainsRegistry`, servlet + reactive `AuthorizationManager`
  implementations.
- `actor-chains.yaml` schema with path-pattern rules, permitted chains,
  `publicAccess` flag, and defaults.
- `zylos.security.actor-chains.enabled` opt-out property.
- ADR 0003: Actor chain design.

### Earlier in this release cycle (already merged)

- JWT validation core
- Repo scaffolding 
