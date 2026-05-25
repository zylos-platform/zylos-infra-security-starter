# ADR 0005: Identity MDC and Metrics

- **Status:** Accepted
- **Date:** 2026-05-25
- **Relates to:** ADR 0001

## Context

Phase 1 architecture requires uniform observability of identity events across every Zylos service:

- **MDC enrichment** so every log line carries the per-request correlation
  ID and the authenticated subject — enabling cross-service log correlation
  via the standard Logstash / Loki pipelines.
- **JWT validation metrics** so the platform can monitor authentication
  health, alert on anomalous failure rates, and dashboard latency
  percentiles.
- **JWKS cache statistics** so key rotation events and cache health are
  visible without ad-hoc instrumentation.

The starter is the natural place for all three: every service inherits it,
so the metric and MDC contracts are stable platform-wide.

## Decision

### 1. MDC enrichment filters

Two filters parallel each other:

- `IdentityMdcFilter` (servlet) — `OncePerRequestFilter` at
  `Ordered.LOWEST_PRECEDENCE`, runs after Spring Security has populated
  the `SecurityContextHolder`.
- `IdentityMdcWebFilter` (reactive) — `WebFilter` at
  `Ordered.LOWEST_PRECEDENCE`, reads the authenticated `SecurityContext`
  via `ReactiveSecurityContextHolder.getContext()`.

Both populate two MDC keys:

- `zylos.correlation_id` — extracted from `X-Correlation-Id` header or
  generated as a UUID. Always echoed in the response header so clients
  share the identifier.
- `zylos.subject` — `Authentication.getName()` when authenticated;
  unset otherwise.

`traceId` and `spanId` are populated by Micrometer Tracing when the
bridge dependency is on the classpath; the starter does not duplicate
that work.

### 2. JWT validation metrics

Two decorators wrap the `JwtDecoder` / `ReactiveJwtDecoder` chain at its
outermost layer (after `UnknownKidRefreshingJwtDecoder`):

- `MeteredJwtDecoder` (servlet)
- `MeteredReactiveJwtDecoder` (reactive)

Both publish:

- `zylos_jwt_validation_total{outcome=success|failure, reason=...}` — counter
- `zylos_jwt_validation_duration_seconds{outcome=success|failure}`
  — timer with percentile histogram

Failure reasons come from `JwtFailureClassifier`, which maps exception
type and message to a bounded category set (`invalid_signature`,
`expired`, `not_yet_valid`, `invalid_audience`, `invalid_issuer`,
`malformed`, `other`). Cardinality is fixed at ≤ 7 reasons × 2 outcomes
= 14 distinct tag combinations per service.

### 3. JWKS cache statistics

`ZylosSecurityCommonAutoConfiguration.jwksCacheMetricsBinder` registers
Micrometer's standard `CaffeineCacheMetrics` binder on the existing
JWKS cache, exposing:

- `cache.gets{cache=zylos_jwks_cache, result=hit|miss}`
- `cache.evictions{cache=zylos_jwks_cache, cause=...}`
- `cache.size`, `cache.load.duration`, `cache.load.failures`

Same pattern the user established for the OPA decision cache in
refactor. Consistent metric naming across both caches simplifies
dashboards.

## Rationale

### Decorator pattern for JWT metrics

Three alternatives were considered:

| Approach                                           | Pros                                                        | Cons                                                                                                            |
|----------------------------------------------------|-------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| **Decorator on `JwtDecoder` (chosen)**             | Captures full validation duration; tight loop around decode | Adds one more layer; lost if user replaces the bean                                                             |
| Spring `Observation` API                           | Modern Micrometer pattern; rich semantics                   | More complex; harder to tag failure reason precisely                                                            |
| Auth event listener (`AuthenticationFailureEvent`) | Decoupled; works for any decoder                            | Loses duration measurement (event fires post-completion); only sees auth-level events, not raw decoder failures |

The decorator approach gives the best signal/effort ratio and aligns with
how the user already structured the JWT decoder chain (multiple decorators).
If a service overrides the `JwtDecoder` bean, it loses metrics — flagged
in the README as the standard "opt-out via override" pattern.

### Standard Caffeine binder for JWKS cache

Dashboards built against the standard
binder convention work for both caches without per-cache customization.

### Reactive MDC via Reactor Context

The conventional pattern for reactive MDC is:

1. Filter writes values to Reactor Context
2. `ThreadLocalAccessor` is registered for each key
3. `Hooks.enableAutomaticContextPropagation()` (or
   `spring.reactor.context-propagation=auto`) bridges Reactor Context to
   MDC across thread hops

The starter registers `ThreadLocalAccessor`s in `IdentityMdcWebFilter`'s
constructor. Consumers must enable automatic context propagation in
their `application.yaml`; we deliberately do **not** enable
`Hooks.enableAutomaticContextPropagation()` from the starter because
that's a JVM-global side effect that should be the consuming service's
explicit choice.

This requirement is documented in the README and called out in the
package-info JavaDoc.

### Subject extraction timing

Both filters need the `SecurityContext` to be populated before they can
read the authenticated subject. Spring Security's filter chain runs
`AuthenticationWebFilter` (reactive) / `BearerTokenAuthenticationFilter`
(servlet) mid-chain; our filters run at `Ordered.LOWEST_PRECEDENCE`,
guaranteed to execute after auth has completed.

## Trade-offs Accepted

- **MDC subject is unavailable in pre-auth filters.** Anything that logs
  before Spring Security's auth filter runs will not have the subject in
  MDC. The correlation ID is still available because it's written first.

- **Reactive subject extraction has a small startup latency cost** because
  `ReactiveSecurityContextHolder.getContext()` returns a `Mono` that must
  resolve before `chain.filter` is subscribed. Order: `~1-10 μs per
  request`. Acceptable given the value of having subject in MDC.

- **Failure classification is heuristic on exception messages.** Same
  caveat as `UnknownKidRefreshingJwtDecoder`'s kid detection. If Nimbus
  or Spring Security changes message formats, our classifier needs to
  update. Tests pin the current formats; CI catches regressions.

- **Metric cardinality is bounded but per-tag-combination Timer
  allocation is lazy.** A service that never sees a particular failure
  reason will never allocate a timer for it. Memory cost is bounded by
  the 14 possible combinations.

- **Decorator lost if user replaces JwtDecoder bean.** Documented in
  README. The decorator chain is reachable via `@ConditionalOnMissingBean`,
  so a service that provides its own `JwtDecoder` bean replaces ours
  wholesale — including the metrics. This is intentional: services that
  fully customize the decoder also customize their observability.

## Observability Inventory

| Metric                                               | Type            | Source                           |
|------------------------------------------------------|-----------------|----------------------------------|
| `zylos_jwt_validation_total{outcome,reason}`         | Counter         | `MeteredJwtDecoder`              |
| `zylos_jwt_validation_duration_seconds{outcome}`     | Timer           | `MeteredJwtDecoder`              |
| `zylos_jwks_forced_refresh_total{decoder}`           | Counter         | `UnknownKidRefreshingJwtDecoder` |
| `cache.gets{cache=zylos_jwks_cache,result}`          | FunctionCounter | `CaffeineCacheMetrics`           |
| `cache.evictions{cache=zylos_jwks_cache,cause}`      | FunctionCounter | `CaffeineCacheMetrics`           |
| `zylos_actor_chain_decisions_total{decision,reason}` | Counter         | `ActorChainEvaluator`            |
| `zylos_opa_decision_duration_seconds{outcome}`       | Timer           | OPA clients                      |
| `cache.gets{cache=zylos_opa_decision_cache,result}`  | FunctionCounter | `CaffeineCacheMetrics`           |

## MDC Keys Inventory

| Key                    | Source                          | Type                       |
|------------------------|---------------------------------|----------------------------|
| `zylos.correlation_id` | `IdentityMdc{Filter,WebFilter}` | UUID or supplied header    |
| `zylos.subject`        | `IdentityMdc{Filter,WebFilter}` | `Authentication.getName()` |
| `traceId`              | Micrometer Tracing              | 16-byte hex                |
| `spanId`               | Micrometer Tracing              | 8-byte hex                 |

Consumers' logback configuration should reference these keys explicitly,
e.g.:

```xml

<pattern>%d{ISO8601} %5p [%X{zylos.correlation_id:-},%X{traceId:-}] %X{zylos.subject:-} %logger{36} - %msg%n</pattern>
```

## References

- Phase 1 architecture (observability)
- ADR 0001: Starter design
- Micrometer Tracing docs: <https://docs.spring.io/spring-boot/reference/actuator/tracing.html>
- Reactor context propagation: <https://projectreactor.io/docs/core/release/reference/#context.api>
