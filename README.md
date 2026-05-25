# zylos-infra-security-starter

> Spring Boot 4 autoconfigured security starter for Zylos backend services.

Every Zylos service that handles JWTs inherits this starter. It provides:

| Capability                 | Default behavior                                                              |
|----------------------------|-------------------------------------------------------------------------------|
| **JWT validation**         | Signature via JWKS, `iss` exact match, `aud == self`, `exp` + 30s skew        |
| **JWKS caching**           | 1-hour Caffeine cache, forced refresh on unknown `kid`                        |
| **Actor chain validation** | Declarative `actor-chains.yaml`; rejects calls from non-permitted callers     |
| **OPA authorization**      | Spring `RestClient` / `WebClient` to centralized OPA, Caffeine decision cache |
| **Identity MDC**           | `subject`, `correlationId`, `traceId` populated for every request             |
| **Identity metrics**       | Micrometer histograms and counters                                            |

## Usage

Three lines in your service's `pom.xml`:

```xml

<dependency>
  <groupId>app.zylos</groupId>
  <artifactId>zylos-infra-security-starter</artifactId>
  <version>${zylos-security-starter.version}</version>
</dependency>
```

Configure in `application.yaml`:

```yaml
zylos:
  security:
    issuer-uri: http://keycloak.zylos.local/realms/zylos
    expected-audience: zylos-internal-myservice
    opa:
      endpoint: http://opa.opa-system.svc.cluster.local:8181
```

The starter autoconfigures the rest.

## Observability

The starter publishes Micrometer metrics and populates the MDC for every
request:

### Metrics

| Metric                                       | Tags             | Source                    |
|----------------------------------------------|------------------|---------------------------|
| `zylos_jwt_validation_total`                 | outcome, reason  | JWT decoder               |
| `zylos_jwt_validation_duration_seconds`      | outcome          | JWT decoder (histogram)   |
| `zylos_jwks_forced_refresh_total`            | decoder          | JWKS cache refresh        |
| `cache.gets{cache=zylos_jwks_cache}`         | result           | JWKS cache                |
| `zylos_actor_chain_decisions_total`          | decision, reason | Actor chain authorization |
| `zylos_opa_decision_duration_seconds`        | outcome          | OPA client (histogram)    |
| `cache.gets{cache=zylos_opa_decision_cache}` | result           | OPA decision cache        |

### MDC keys

- `zylos.correlation_id` — per-request correlation ID (extracted from
  `X-Correlation-Id` header or generated)
- `zylos.subject` — authenticated subject when present
- `traceId`, `spanId` — populated by Micrometer Tracing (not the starter)

### Reactive context propagation requirement

For the reactive stack, consumers must enable Reactor's automatic
context propagation so MDC values are bridged across thread hops:

```yaml
spring:
  reactor:
    context-propagation: auto
```

Without this, the values reach the Reactor Context but are not bridged
into MDC for log statements.

### Logback example

```xml

<pattern>%d{ISO8601} %5p [%X{zylos.correlation_id:-},%X{traceId:-}] %X{zylos.subject:-} %logger{36} - %msg%n</pattern>
```

## Wiring into a Service

The starter autoconfigures the JWT decoder and the `ActorChainAuthorizationManager`
bean. Wire the manager into your service's security filter chain explicitly so
you retain control of CSRF, CORS, and other security concerns:

```java

@Configuration
class SecurityConfig {

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http, ActorChainAuthorizationManager actorChain) throws Exception {
    http.oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()))
      .authorizeHttpRequests(authz -> authz
        .requestMatchers("/api/**").access(actorChain)
        .anyRequest().permitAll());
    return http.build();
  }
}
```

Provide an `actor-chains.yaml` on the classpath, or set
`zylos.security.actor-chains.enabled=false` to disable chain validation
for this service.

## Architecture

The starter is part of the Zylos Identity & Security Spine. See:

- [Architecture (zylos-infra-gitops)](https://github.com/zylos-platform/zylos-infra-gitops/blob/main/docs/architecture/phase-1.md)
- [ADR 0001: Starter Design](docs/adr/0001-starter-design.md)

## Compatibility

- Java 25 LTS
- Spring Boot 4.0.6+
- Spring Security 7.0+
- Both servlet (Spring MVC) and reactive (WebFlux) stacks

## Development

```bash
./mvnw verify  # build + test + 85% coverage gate
```

## License

[MIT](LICENSE)
