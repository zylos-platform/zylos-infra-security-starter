# ADR 0001: zylos-infra-security-starter — Overall Design

- **Status:** Accepted
- **Date:** 2026-05-13

## Context

The Zylos Identity & Security Spine requires every backend service to enforce — uniformly and provably — JWT validation, audience binding, actor chain validation, and OPA-mediated authorization. Re-implementing this in each service is operationally fragile: variance in implementation creates security drift; bug fixes require coordinated rollouts across N services; and onboarding a new service requires repeating non-trivial security setup.

A single Spring Boot starter that every service inherits centralizes the security stack into one library. Improvements propagate via a dependency bump. New services get a correct security baseline by default.

## Decision

Ship `zylos-infra-security-starter` as a dedicated Spring Boot 4 auto-configured starter that every Zylos backend service inherits. The starter delivers:

## Rationale

**Separate repo, not a Maven module.** The starter is large enough and high-stakes enough to warrant its own repo with its own release cadence. The parent POM stays focused on inheritance contracts; the starter is a consumable library. This separation also lets the starter version independently of parent POM bumps.

**No external OPA SDK dependency.** OPA's REST API (`POST /v1/data/{path}`) is trivially simple. The official `io.github.open-policy-agent:opa:2.2.0` SDK has near-zero open-source adoption (0 components on Maven Central depend on it), a Jackson version skew with Spring Boot 4, and we'd wrap it for Caffeine caching, Resilience4j, and Micrometer anyway. Rolling a ~100 LOC `RestClient`/`WebClient`-based client gives full control with cleaner Spring idioms. Detailed analysis in ADR 0004.

**Both servlet and reactive stacks supported.** Spring Cloud Gateway is reactive (WebFlux). Domain services are servlet (Spring MVC). Two parallel auto-configuration classes (`ZylosSecurityServletAutoConfiguration`, `ZylosSecurityReactiveAutoConfiguration`) share core validators (issuer/audience/skew/JWKS/actor-chain) and diverge only at the HTTP-layer integration. `@ConditionalOnWebApplication(type = SERVLET)` and `@ConditionalOnWebApplication(type = REACTIVE)` discriminate.

**85% line-coverage gate (vs parent's 70%).** Every Zylos service depends on this starter. Quality compounds. A bug here is a bug everywhere. The stricter gate is justified by the radius of impact.

**No Lombok.** Java 25 records cover the use cases (DTOs, value types). Avoiding Lombok keeps the build straightforward (no extra annotation processor with classpath quirks), makes ArchUnit rules easier to reason about, and aligns with the broader Zylos Java standard.

**JSpecify null-safety on all public API.** Every package is `@NullMarked` by default; nullable types are explicit. Strict null discipline catches a category of bugs at compile time and serves as machine-readable API documentation.

## Trade-offs Accepted

- **Tight coupling between services and the starter.** Every service that consumes the starter is locked to its evolution. Mitigation: SemVer discipline; breaking changes require a major version bump and migration ADR.
- **Auto-configuration discoverability.** Spring Boot auto-config is implicit. Developers may not realize what the starter does without reading docs. Mitigation: `application.yaml` reference; clear NOTES in service templates; ArchUnit guard at the parent level ensuring the starter is always present.

## Out of Scope for v0.x

- Distributed tracing instrumentation (provided by Spring Boot 4's `spring-boot-starter-actuator` + Micrometer Tracing already; not duplicated here)
- Rate limiting (gateway responsibility, not service responsibility)
- TLS / mTLS (mesh-layer concern: Istio ambient ztunnel)
- Refresh-token handling (BFF-layer concern: Next.js BFF)

## References

- Phase 1 architecture (zylos-infra-gitops/docs/architecture/phase-1.md)
- ADR 0010 (zylos-infra-gitops): OAuth flows per client type
- ADR 0011 (zylos-infra-gitops): RFC 8693 token exchange
- ADR 0012 (zylos-infra-gitops): Refresh token reuse detection
