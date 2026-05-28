# Documentation

## Architecture Decisions

- [ADR 0001: Starter Design](adr/0001-starter-design.md)
- [ADR 0002: JWT Validation Chain Design](adr/0002-jwt-validation-design.md)
- [ADR 0003: Actor Chain Registry and Authorization Manager](adr/0003-actor-chains-design.md)
- [ADR 0004: OPA Integration Pattern](adr/0004-opa-integration.md)
- [ADR 0005: Identity MDC and Metrics](adr/0005-identity-mdc-and-metrics.md)
- [ADR 0006: Integration Test Scaffolding](adr/0006-integration-test-scaffolding.md)

## Status

**Sub-phase complete.** The security starter provides JWT validation
(signature, issuer, `aud == self`, clock skew, JWKS cache with unknown-kid
refresh), actor-chain authorization (model — opt-in `chainSensitive`
matching), OPA integration (servlet + reactive clients with Caffeine decision
cache), and identity observability (MDC enrichment + Micrometer metrics).
Verified by unit tests (≥85% coverage) and Testcontainers integration tests
against real Keycloak 26.6.1.

Consumed by services from Sub-phase (gateway) onward. The RFC 8693 `act`
claim it validates is populated in production by the ActClaimMapper
(`zylos-infra-keycloak-extensions`, single-hop; see that repo's ADR 0001).
