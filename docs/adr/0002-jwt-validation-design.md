# ADR 0002: JWT Validation Chain Design

- **Status:** Accepted
- **Date:** 2026-05-13
- **Relates to:** ADR 0001

## Context

Every Zylos service that handles JWTs must enforce — uniformly and provably — issuer match, audience binding (aud ==
self), and time bounds with a 30-second clock skew. Architecture further requires graceful handling of JWKS key
rotation: when an inbound token's `kid` is not in the cached JWKS, the cache must refresh transparently rather than
rejecting the token until the TTL expires.

Spring Security 7's `NimbusJwtDecoder` provides most of this out of the box:

- `.cache(Cache)` injects a Spring cache for JWKS results
- `JwtTimestampValidator(Duration)`, `JwtIssuerValidator(String)` are stock
- Validator composition via `DelegatingOAuth2TokenValidator`

But two gaps remain:

1. The stock `JwtClaimValidator<List<String>>` for `aud` is awkward (the claim can be String or List in JWT-land;
   behavior differs).
2. The built-in JWKS cache does **not** auto-refresh on unknown `kid`. A freshly-rotated signing key causes 401
   responses until the cache TTL (default 5 minutes) expires.

## Decision

Three deliverables:

1. **`AudienceValidator`** — purpose-built `OAuth2TokenValidator<Jwt>` that checks the `aud` claim contains the
   configured `expectedAudience`. Always treats `aud` as a list (the canonical JWT shape). Emits error code
   `invalid_audience` with the expected audience in the description for observability.

2. **JWKS cache** — Caffeine-backed Spring `Cache` (1-hour TTL by default, 16-entry max — services rarely talk to more
   than one issuer). Injected into `NimbusJwtDecoder.withIssuerLocation(...).cache(jwksCache)`.

3. **`UnknownKidRefreshingJwtDecoder` decorator** — wraps the configured `JwtDecoder`. On `BadJwtException` whose
   message indicates a kid issue, evicts the JWKS cache entry (forcing the next call to re-fetch from upstream) and
   retries the decode exactly once. Single-flight within a JVM is guaranteed by Nimbus's internal locking. A parallel
   `UnknownKidRefreshingReactiveJwtDecoder` handles the reactive stack identically.

The full validator chain (assembled by both auto-configurations):

1. `JwtTimestampValidator(clockSkew)` — 30 s default skew
2. `JwtIssuerValidator(issuerUri)` — exact match
3. `AudienceValidator(expectedAudience)` — `aud == self`
4. Any extra `OAuth2TokenValidator<Jwt>` beans in the context

Wrapped by `DelegatingOAuth2TokenValidator` and set on the decoder via `setJwtValidator(...)`.

## Rationale

- **Purpose-built `AudienceValidator`** is more readable than the generic `JwtClaimValidator<List<String>>` and provides
  better error messages. Cost is ~50 LOC.

- **Caffeine for JWKS cache.** Caffeine is the best Java caching library; Spring Boot's `CaffeineCache` adapter is
  the idiomatic bridge to the Spring `Cache` interface. We get LRU + time eviction + stats out of the box.

- **Decorator pattern for unknown-kid refresh.** A decorator is simpler than customizing Nimbus's internals (
  `JWKSource`, `JWTProcessor`). It composes cleanly with the standard `NimbusJwtDecoder` pipeline. Trade-off: detection
  is heuristic on the exception message; if Spring Security or Nimbus changes the message format, our detection breaks.
  We accept this risk because the consequence is a temporary 401 storm rather than a security gap; coverage in
  `UnknownKidRefreshingJwtDecoderTest` reduces regression risk.

- **Identical reactive variant.** Spring Cloud Gateway uses the reactive stack. The reactive decorator is structurally
  identical to the servlet one; copy-paste is justified by the fact that the two `ReactiveJwtDecoder` and `JwtDecoder`
  interfaces are intentionally disjoint in Spring Security.

- **`ObjectProvider<OAuth2TokenValidator<Jwt>>` for extra validators.** Services can drop in a `@Bean` of type
  `OAuth2TokenValidator<Jwt>` to extend the validator chain without subclassing or excluding the starter. This is the
  extension point for actor-chain validator and any service-specific custom validators.

## Trade-offs Accepted

- **Heuristic message-based unknown-kid detection.** A future improvement could pre-parse the JWT header to extract the
  kid before passing to the inner decoder, then check against a tracked kid set. For Phase 1, the message-based
  heuristic is sufficient and well-tested. The detection patterns cover Nimbus's current message formats: "No matching
  JWK", "No matching key(s) found", "Couldn't retrieve remote JWK set".

- **Single-flight only within a JVM.** Each replica may independently re-fetch JWKS on a key rotation event. Total
  upstream load is bounded (≤ N requests for N replicas, once per rotation). Cross-JVM single-flight
  would require distributed coordination, out of scope for Phase 1.

- **Reactive decoder does not currently inject the Spring `Cache` directly.** `NimbusReactiveJwtDecoder` does not expose
  `.cache(Cache)` in Spring Security 7.0.x. The reactive decoder uses Nimbus's built-in 5-minute in-process cache; the
  refreshing decorator's eviction still triggers a fresh fetch on next call because the Spring `Cache` is consulted
  prior to Nimbus's. Phase 1 design accepts the 5-minute internal cache because the refreshing decorator covers the
  rotation window.

## Verification

- Unit tests in `AudienceValidatorTest` and `UnknownKidRefreshingJwtDecoderTest` cover happy path, claim-mismatch,
  exception classification, retry semantics, and cache eviction.
- Auto-configuration tests in `ZylosSecurityAutoConfigurationTest` use `ApplicationContextRunner` + WireMock to verify
  the entire bean graph wires correctly with realistic Keycloak metadata.
- Integration tests against a real Keycloak container ship.

## References

- Spring Security 7.0 docs: <https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html>
- Architecture (token validation), (JWKS caching)
- ADR 0001: Starter overall design
