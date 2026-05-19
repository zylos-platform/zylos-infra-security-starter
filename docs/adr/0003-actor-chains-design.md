# ADR 0003: Actor Chain Registry and Authorization Manager

- **Status:** Accepted
- **Date:** 2026-05-14
- **Relates to:** ADR 0011 (zylos-infra-gitops; RFC 8693 token exchange)

## Context

Phase 1 requires services to validate the full delegation chain
expressed in a token's RFC 8693 `act` claim against a declarative
per-endpoint policy. A request whose chain doesn't match any permitted
chain is rejected with HTTP 403.

RFC 8693 itself is normatively narrower: it says **only the current actor
MUST be considered for access decisions; prior actors are informational
only.** Our policy goes beyond the RFC by treating the full chain as
authorization material. This is a defensible defense-in-depth choice — it
catches a category of misconfiguration (a service reachable from a caller
not in its expected graph) that the standard alone doesn't cover — but the
non-standard nature must be made explicit.

## Decision

Implement actor-chain authorization as a Spring Security
**`AuthorizationManager`** (servlet) / **`ReactiveAuthorizationManager`**
(reactive), not as an `OAuth2TokenValidator<Jwt>`. Rationale:

- The check depends on the **request path**, not just the token. Token
  validators don't see the request; authorization managers do.
- The outcome is **HTTP 403** (authorization), not 401 (authentication),
  which is the semantically correct status for "you are who you say but
  you're not allowed to be here this way."
- It fits the Spring Security extension model: services wire the manager
  into their security filter chain alongside other authz rules.

### Chain Extraction

`ActChainExtractor` walks the `act` claim from outermost (most recent
actor) to innermost (least recent), accumulates `(client_id, sub)` pairs,
then reverses to **chronological order** (least-recent first). This is the
order in which permitted-chains are written in `actor-chains.yaml`, which
matches the human intuition of "gateway then catalog then pricing."

Two pragmatic guards:

- **Max-depth cap** (constant `MAX_DEPTH = 20`) prevents stack abuse from
  pathologically deep `act` nesting.
- **Consecutive-duplicate collapse**: per the open OAuth WG issue, a
  client exchanging its own token multiple times produces consecutive
  duplicates. We collapse these into a single logical hop. Non-consecutive
  duplicates (e.g., `A → B → A`) are preserved because they represent
  real delegation round-trips.

### Identity Matching

Each `ActorPrincipal` exposes a `matchKey()` that prefers `client_id`
over `sub`. Permitted chains in `actor-chains.yaml` are written in
client-id terms (`zylos-gateway`, `zylos-internal-cart`, …). Keycloak's
V2 token exchange populates both `client_id` and `sub` (service-account
form) in each `act` entry; we use `client_id` first because it directly
maps to our realm client identifiers. If `client_id` is absent for any
reason, we fall back to `sub`.

### YAML Schema

```yaml
defaults:
  rejectIfNoPathMatch: true
  allowEmptyChain: false
  maxChainDepth: 5

endpoints:
  - pathPattern: /api/v1/hello/me
    permittedChains:
      - [ zylos-gateway ]
      - [ zylos-mobile-bff, zylos-gateway ]
  - pathPattern: /api/v1/hello/public
    publicAccess: true
```

Path patterns use Spring's `PathPattern` syntax (the modern replacement
for `AntPathMatcher`, used by both servlet and reactive stacks). First
match wins — order rules from specific to general.

### Decision Flow

1. Match path against registered rules in declaration order.
2. If matched rule has `publicAccess: true` → permit.
3. If no rule matches and `defaults.rejectIfNoPathMatch` is true → deny.
4. Extract chain from JWT.
5. If chain length > `defaults.maxChainDepth` → deny.
6. If chain is empty and `defaults.allowEmptyChain` is false → deny.
7. If chain equals any permitted chain by match key → permit.
8. Otherwise → deny.

### Activation

Controlled by `zylos.security.actor-chains.enabled` (default `true`).
When enabled, `classpath:actor-chains.yaml` must exist or the application
fails to start. Services with no chain requirements set the property to
`false`.

### Wiring into a Service

The starter exposes the manager as a bean. Services wire it explicitly in
their security configuration:

```java

@Bean
SecurityFilterChain filterChain(HttpSecurity http, ActorChainAuthorizationManager actorChain) throws Exception {
  http.oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()))
    .authorizeHttpRequests(authz -> authz
      .requestMatchers("/api/**").access(actorChain)
      .anyRequest().permitAll());
  return http.build();
}
```

We don't autoconfigure the SecurityFilterChain itself because services
have legitimate variation in their security chains (CSRF settings, CORS,
additional authz rules). Manual wiring keeps that flexibility while still
making the chain validator a single import.

## Rationale

- **Path-aware policy over a global "any chain depth ≤ N" rule.** Different
  endpoints have different exposure surfaces; admin endpoints permit only
  direct gateway calls, cart endpoints permit gateway-via-bff, etc. A
  global rule can't express this.

- **`PathPattern` over `AntPathMatcher`.** PathPattern is the modern
  replacement, used by both Spring MVC and WebFlux. AntPathMatcher remains
  for backward compatibility but is no longer the preferred API.

- **`first-match-wins` over best-match.** Best-match resolution requires
  pattern-specificity comparisons (which Spring does support, but with
  surprising edge cases). First-match makes ordering explicit and the
  YAML file self-documenting.

## Trade-offs Accepted

- **Going beyond the RFC.** Phase 1 enforces a policy stricter than
  RFC 8693's normative requirements. Documented here so the divergence is
  intentional and visible. Services unable or unwilling to enforce this
  can disable via `zylos.security.actor-chains.enabled=false`.

- **No service-default chains.** Every service maintains its own
  `actor-chains.yaml` listing every endpoint that requires validation.
  This is intentional: chain policy is per-service domain knowledge, not
  a platform-wide concern. The tradeoff is some duplication across
  services that share an interface shape (e.g., all CRUD services), which
  could be addressed in a later phase with a shared base YAML mechanism.

- **No hot reload.** Reloading `actor-chains.yaml` requires a pod restart.
  Acceptable for Phase 1; chain policy is high-stakes and intentional
  changes warrant a deployment.

- **String-equality chain matching only.** No wildcards within chain
  entries (e.g., `[zylos-gateway, zylos-internal-*]`). Could be added if
  a need emerges.

## Observability

Two Micrometer counters track decisions:

- `zylos_actor_chain_decisions_total{decision="permit"}` — permitted requests
- `zylos_actor_chain_decisions_total{decision="deny",reason="..."}` —
  denials with reason tag (`no_matching_rule`, `chain_too_deep`,
  `empty_chain`, `chain_mismatch`, `no_jwt`)

Logged at INFO for denials, DEBUG for permits.

## References

- RFC 8693 4.1: <https://datatracker.ietf.org/doc/html/rfc8693#section-4.1>
- Spring Security 7 `AuthorizationManager` docs
