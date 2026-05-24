# ADR 0004: OPA Integration Pattern

- **Status:** Accepted
- **Date:** 2026-05-24
- **Relates to:** ADR 0001

## Context

Phase 1 requires every Zylos service to perform fine-grained
authorization decisions via OPA. The architecture mandates:

- p99 latency < 5 ms on cache miss
- p99 latency < 1 ms on cache hit
- Caffeine-backed decision cache, 30 s TTL, 50,000 entries
- Negative caching (cached denials and exceptions)
- Both servlet (Spring MVC) and reactive (WebFlux / Spring Cloud Gateway)
  stacks supported

We evaluated two integration paths and chose to roll our own thin client
rather than depend on an external OPA Java SDK.

## Decision

Hand-rolled `OpaClient` interface with three implementations layered in a
decorator chain:

```
CachingOpaClient (Caffeine, 30s TTL, 50k entries, negative caching)
↓
{RestClient | WebClient}OpaClient  (HTTP client backend)
↓
OPA REST API: POST /v1/data/{policyPath}
```

Backend selection is automatic: when WebFlux is on the classpath, the
WebClient backend is used; else, the RestClient backend.

## Rationale

### Why not the OPA Java SDK?

We evaluated `io.github.open-policy-agent:opa:2.2.0` (the official SDK,
recently transferred from the StyraInc commercial org to the open-policy-
agent upstream organization). Several signals discouraged adoption:

| Signal                        | Detail                                                                                                                                      |
|-------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| Maven Central "Used in" count | **0 components**                                                                                                                            |
| GitHub stars                  | 25                                                                                                                                          |
| Open issues                   | 4                                                                                                                                           |
| Adoption signal               | No major enterprise OPA consumers cite this SDK; standard practice is to call the REST API directly                                         |
| Technical smell               | Pins Jackson 2.17.0/2.18.2 (vs Spring Boot 4's managed Jackson) — `dependencyConvergence` enforcer conflict                                 |
| Technical smell               | `junit-jupiter-engine` declared at `runtime` scope (test dependency leaking)                                                                |
| Coverage need                 | We'd wrap the SDK anyway with our own Caffeine cache, Resilience4j circuit breaker, and Micrometer metrics — SDK adds only a thin DTO layer |

For an enterprise platform, a hand-rolled ~100 LOC client is
the better choice. It gives full control over caching, retries, timeouts,
observability; eliminates a low-adoption transitive dependency; and uses
Spring idioms throughout.

### Why both RestClient and WebClient backends?

The Zylos backend stack is bimodal: Spring Cloud Gateway is reactive
(WebFlux); all domain services are servlet (Spring MVC).

### Why these specific timeouts?

- **Connect: 500 ms** — generous for in-cluster service-to-service over
  the Istio ambient mesh (sub-10 ms typical)
- **Read: 1 s** — generous against the 5 ms p99 SLO; designed to fail
  fast if OPA is genuinely unhealthy without false-positive timeouts
  during a cluster pause / GC

These align with architecture ("hard timeout: 1s") and are
configurable via `zylos.security.opa.connect-timeout` and `read-timeout`.

### Why Caffeine over Spring's Cache abstraction?

The JWKS cache uses Spring's `Cache` abstraction because
`NimbusJwtDecoder.cache(Cache)` accepts that interface directly. The OPA
cache has no such external integration point, so we use Caffeine
directly. This:

- Gives access to advanced features (statistics, async loading,
  refresh-after-write) without going through Spring's adapter layer
- Reduces one indirection in the hot path
- Makes the test setup simpler (no `CaffeineCache` wrapper class)

### Why negative caching?

A flood of denied requests against the same policy path with the same
input is a real failure mode (e.g., a misconfigured client hammering an
endpoint it can't access). Without negative caching, every denied
request hits OPA, doubling its load. With 30 s negative caching, the
caller's failure self-rate-limits.

The same TTL applies to OPA exceptions (unreachable, server error). If
OPA is fully down, the first call's exception is cached for 30 s; the
service keeps emitting deny decisions to consumers (via `check()`'s
fail-closed semantics) instead of repeatedly retrying a dead OPA.

## Trade-offs Accepted

- **Cache key includes the input object's `equals`/`hashCode`.** Consumers
  must pass stable inputs (records are ideal; mutable POJOs are a foot-gun). Documented in `OpaClient.evaluate` javadoc.

- **No request-batching.** OPA supports batched data API calls; we don't
  use this in Phase 1. Future optimization if profiling shows per-call
  HTTP overhead becoming significant.

- **No circuit breaker.** Resilience4j circuit breaker around
  the inner client is planned but deferred to a later PR; the negative
  cache provides similar properties (30 s of stable deny when OPA is
  down) without the configuration surface.

## Observability

Three Micrometer metrics, all consistent with Phase 1 architecture:

| Metric                                | Type              | Tags                        |
|---------------------------------------|-------------------|-----------------------------|
| `zylos_opa_decision_duration_seconds` | Timer (histogram) | `outcome={success,failure}` |
| `zylos_opa_decision_cache`            | Counter           | `outcome={hit,miss}`        |

## References

- Phase 1 architecture (OPA integration),  (observability)
- ADR 0001: Starter overall design
- OPA data API: <https://www.openpolicyagent.org/docs/latest/rest-api/#data-api>
- Spring Boot 4 RestClient timeout configuration: <https://docs.spring.io/spring-boot/reference/io/rest-client.html>
