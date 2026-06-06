package app.zylos.security.properties;

import java.net.URI;
import java.time.Duration;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration properties for the Zylos security starter, bound under the
 * {@code zylos.security} prefix.
 *
 * <p>All fields are mandatory unless documented otherwise; validation runs at
 * context startup so misconfiguration fails fast.
 *
 * @param issuerUri        exact {@code iss} value the realm publishes; tokens with a
 *                         different issuer are rejected with HTTP 401
 * @param jwkSetUri        optional direct JWKS (certs) endpoint for fetching signing
 *                         keys, decoupled from {@code issuerUri}. When set, the decoder
 *                         fetches keys here and skips OIDC discovery; {@code iss} is
 *                         still validated against {@code issuerUri}. Use in split-horizon
 *                         topologies where in-cluster pods reach Keycloak at a different
 *                         URL than the public issuer. When null, discovery via
 *                         {@code issuerUri} is used.
 * @param expectedAudience the {@code aud} claim value this service identifies
 *                         as; tokens with any other audience are rejected
 * @param clockSkew        permissive window for {@code exp}/{@code nbf} validation;
 *                         30 seconds matches the Zylos NTP discipline
 * @param jwksCache        JWKS caching configuration; reasonable defaults provided
 * @param actorChains      location of {@code actor-chains.yaml} on the classpath
 * @param opa              OPA endpoint configuration
 */
@Validated
@ConfigurationProperties(prefix = "zylos.security")
public record ZylosSecurityProperties(
        @NotBlank String issuerUri,
        @Nullable String jwkSetUri,
        @NotBlank String expectedAudience,
        @DefaultValue("30s") Duration clockSkew,
        @DefaultValue JwksCacheProperties jwksCache,
        @DefaultValue ActorChainsProperties actorChains,
        @DefaultValue OpaProperties opa,
        @DefaultValue MdcProperties mdc) {

    /**
     * JWKS cache settings. The cache is a Caffeine-backed Spring {@link
     * org.springframework.cache.Cache} handed to {@code NimbusJwtDecoder}.
     */
    public record JwksCacheProperties(
            @DefaultValue("1h") Duration ttl,
            @DefaultValue("16") @Min(1) long maxEntries) {}

    /**
     * Location of the actor-chains YAML.
     */
    public record ActorChainsProperties(
            @DefaultValue("true") boolean enabled,
            @DefaultValue("classpath:actor-chains.yaml") String location) {}

    /**
     * OPA endpoint, timeouts, and decision-cache settings.
     */
    public record OpaProperties(
            @Nullable URI endpoint,
            @DefaultValue("500ms") Duration connectTimeout,
            @DefaultValue("1s") Duration readTimeout,
            @DefaultValue("30s") Duration cacheTtl,
            @DefaultValue("50000") @Min(0) int cacheMaxSize) {}

    /**
     * MDC enrichment settings.
     */
    public record MdcProperties(
            @DefaultValue("true") boolean enabled,
            @DefaultValue("X-Correlation-Id") String correlationIdHeader) {}
}
