# Changelog

All notable changes to `zylos-infra-security-starter` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- MDC enrichment filters (servlet + reactive) populating
  `zylos.correlation_id` and `zylos.subject` per request.
- JWT validation metrics: `zylos_jwt_validation_total` and
  `zylos_jwt_validation_duration_seconds` via decorator pattern.
- JWKS cache statistics via standard `CaffeineCacheMetrics` binder.
- `MdcKeys` public constants for consumers' logback configuration.
- `JwtFailureClassifier` mapping JWT validation failures to bounded
  category tags for low-cardinality metrics.
- ADR 0005: Identity MDC and metrics.

### Earlier in this release cycle (already merged)

- JWT validation core
- Repo scaffolding 
