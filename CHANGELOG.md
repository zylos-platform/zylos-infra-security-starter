# Changelog

All notable changes to `zylos-infra-security-starter` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Testcontainers-based integration tests against real Keycloak 26.6.1:
  end-to-end JWT validation (`JwtIntegrationIT`) and actor-chain
  authorization with real RFC 8693 token exchange (`ActorChainIntegrationIT`).
- `KeycloakIntegrationTestBase` shared base class with singleton container
  pattern and helpers for token acquisition + RFC 8693 exchange.
- `@IntegrationTest` composite annotation (`@SpringBootTest` + `@Testcontainers`).
- Test realm at `src/test/resources/keycloak/test-realm.json` with three
  V2-token-exchange-enabled clients.
- Failsafe plugin configuration to run `*IT.java` during `mvn verify`.
- ADR 0006: Integration test scaffolding.

### Earlier in this release cycle (already merged)

- JWT validation core
- Repo scaffolding 
