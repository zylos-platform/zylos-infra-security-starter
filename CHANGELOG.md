# Changelog

All notable changes to `zylos-infra-security-starter` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OPA integration: `OpaClient` interface with `RestClient`-based (servlet)
  and `ReactiveOpaClient` interface with `WebClient`-based (reactive) backends; `CachingOpaClient` decorator
  with Caffeine (30 s TTL, 50k entries, negative caching).
- Autoconfiguration: `OpaClient` bean exposed when
  `zylos.security.opa.endpoint` is set.
- Micrometer metrics: `zylos_opa_decision_duration_seconds`,
  `zylos_opa_decision_cache`.
- ADR 0004: OPA integration pattern.

### Earlier in this release cycle (already merged)

- JWT validation core
- Repo scaffolding 
