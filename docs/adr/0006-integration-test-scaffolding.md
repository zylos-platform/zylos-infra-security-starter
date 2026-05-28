# ADR 0006: Integration Test Scaffolding

- **Status:** Accepted
- **Date:** 2026-05-25
- **Relates to:** ADR 0001, ADR 0002, ADR 0003

## Context

The starter has comprehensive unit tests (≥85% line coverage) using
WireMock for JWKS / OPA mocking and Mockito for collaborator mocks. Unit
tests verify each component in isolation; they do not verify that the
full Spring autoconfiguration wires correctly against a real OAuth2
identity provider, that real Keycloak-issued tokens validate end-to-end,
or that RFC 8693 token exchange produces tokens with the `act` claim
shape our extractor expects.

Phase 1 (Spring Cloud Gateway) and (`zylos-service-secured-hello`)
will consume the starter. Before they do,
we need confidence that the starter works against real components — not
just its unit-tested mocks.

## Decision

Add integration tests using **Testcontainers** with the **dasniko
testcontainers-keycloak** community module, running against a real
Keycloak 26.6.1 container.

### Architectural choices

**Singleton container per JVM, not per-test-class.** The shared
`KeycloakIntegrationTestBase` instantiates and starts the container in
a `static` initializer. All `*IT.java` classes extend the base. The
container lives for the entire test JVM, amortizing the ~10-second
startup cost across all integration tests.

**Realm import from JSON, not programmatic admin API.** The test realm
is committed to `src/test/resources/keycloak/test-realm.json` in
Keycloak's standard realm-export format. Three confidential clients
(`zylos-internal-test`, `zylos-gateway`, `zylos-internal-caller`) with
V2 token exchange enabled, one role, one user — minimum needed to test
the validator chain and one- and two-hop actor chains.

**Real RFC 8693 token exchange, not synthesized JWTs.** Tests acquire
real tokens via `client_credentials`, then perform real token exchange
via Keycloak's standard token endpoint. The resulting tokens have
properly-populated `act` claims that the extractor and registry process
identically to production tokens. This validates the entire claim path
end-to-end.

**Failsafe plugin, `*IT.java` suffix.** Integration tests run during
`mvn verify`, not `mvn test`. Failsafe's separate test-result handling
means CI can report unit and integration failures distinctly. The
`*IT.java` suffix is failsafe's default pattern.

**`@IntegrationTest` composite annotation.** Combines `@SpringBootTest`,
`@Testcontainers`, and `@Tag("integration")` for filterable test
execution.

**Programmatic registry construction in actor-chain tests.** Rather
than authoring multiple test YAML files for different scenarios, the
actor-chain integration tests construct `ActorChainsRegistry`
programmatically. The YAML loader is already covered by unit tests
(`ActorChainsLoaderTest`); integration tests focus on the auth manager's
behavior against real token shapes.

## Rationale

- **`dasniko/testcontainers-keycloak` over generic `GenericContainer`.**
  The dasniko module is the established community standard. Version
  3.8.0 supports Keycloak 22+; 26.6.1 is well within range. Encapsulates
  Keycloak-specific concerns (admin user, JWKS path, realm import) so
  test code stays focused on the SUT.

- **Test realm is minimal.** Three clients, not the six of the production
  zylos realm. Test scenarios that need a different shape (e.g., the
  storefront BFF) can extend the realm or override via Keycloak admin
  API. Smaller realm = faster import.

- **No OPA in starter integration tests.** OPA-related code (HTTP
  clients, caching) is fully covered by unit tests with WireMock. End-
  to-end OPA tests will happen at the service level (`zylos-service-secured-hello`),
  where there's a real policy to evaluate.

- **No MDC integration tests.** MDC behavior depends on the consuming
  service's logback configuration, which isn't part of the starter.
  Unit tests verify the filters write to MDC / Reactor Context
  correctly; consuming services verify their logs include the keys.

## Trade-offs Accepted

- **Test execution time.** Integration tests run ~30 seconds total
  (10s Keycloak startup + ~2s per test for token acquisition over HTTP).
  Mitigated by singleton container pattern and parallel test execution
  within a class.

- **Docker dependency in CI.** Failsafe phase requires Docker on the
  CI runner. GitHub Actions provides this on `ubuntu-latest`; the
  starter's CI workflow already includes it.

- **Keycloak version drift.** Pinned to 26.6.1 in both the integration
  tests and the production realm. Bumping requires updating both
  places; CI catches mismatches via test failure.

- **No coverage for unhappy network paths.** Integration tests assume
  Keycloak is reachable. Network-failure scenarios (timeouts,
  unreachable JWKS endpoint, etc.) are covered by unit tests with
  WireMock fault injection.

## What's Tested

| Test class                | Scenarios                                                                                                                                               |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `JwtIntegrationIT`        | Valid token decode; wrong audience rejected; malformed token rejected; invalid-signature token rejected; cache reuse on repeated decode                 |
| `ActorChainIntegrationIT` | Single-hop chain permitted; two-hop chain permitted; mismatched chain denied; public endpoint permits without token; no matching path denied by default |

## Coverage and the Real-`act` Boundary

After the refinement (chain matching opt-in via `chainSensitive`), the
actor-chain integration tests (`ActorChainIntegrationIT`) cover the decision
flow that does not require a populated `act` claim:

- public access (permit without token);
- non-chain-sensitive endpoints (authenticated-only permit) with a real token;
- standard default (unmatched path permits an authenticated caller);
- chain-sensitive wiring with the empty-chain guard firing on a real, act-less
  token;
- strict no-match deny;
- chain-sensitive unauthenticated deny.

### Why the positive chain-match path is not tested here

The security starter's integration tests run against **vanilla Keycloak**
(`quay.io/keycloak/keycloak`) via the dasniko Testcontainers module. Vanilla
Keycloak does not populate the RFC 8693 `act` claim — that's the entire reason
the ActClaimMapper exists (zylos-infra-keycloak-extensions). So a positive
chain-match (populated `act` equal to a permitted chain) cannot be produced
here without either:

- **(a)** adding a cross-repo test dependency on the published mapper JAR
  (requires GitHub Packages authentication in CI even for public packages), or
- **(b)** running the custom production image in the dasniko container (which
  bakes `KC_DB=postgres` via `kc.sh build` and conflicts with the container's
  dev-mode startup).

Both costs are disproportionate because the path is already covered in pieces:

| Layer                                          | Test                                                                               |
|------------------------------------------------|------------------------------------------------------------------------------------|
| Mapper produces correctly-shaped `act`         | `ActClaimMapperIT` (keycloak-extensions) — real exchange                           |
| Extractor parses that `act` format             | `ActChainExtractorTest` (synthesized, matching documented format)                  |
| Matcher matches chain to permitted chains      | `ActorChainEvaluatorTest`, `ActorChainAuthorizationManagerTest`                    |
| Full wiring (real `act` → real decode → authz) | **Deferred to Sub-phase** service test against the cluster's custom Keycloak image |

This is a deliberate boundary, not a coverage gap: every layer is tested, and
the full real-`act` wiring is validated at the service level in Sub-phase
where the custom image runs natively.

### Future option

If end-to-end real-`act` coverage is wanted inside the starter before
Sub-phase, add an opt-in test tagged `@Tag("real-mapper")` that mounts the
mapper JAR into the vanilla container and is skipped by default in CI. This was
considered and deferred.

## References

- Phase 1 architecture (validation, token exchange, JWKS)
- ADR 0001 (starter design), ADR 0002 (JWT validation), ADR 0003 (actor chains)
- dasniko/testcontainers-keycloak: <https://github.com/dasniko/testcontainers-keycloak>
- Testcontainers singleton
  pattern: <https://java.testcontainers.org/test_framework_integration/manual_lifecycle_control/>
