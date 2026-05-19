package app.zylos.security.properties;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.URI;
import java.time.Duration;

/**
 * Configuration properties for the Zylos security starter, bound under the
 * {@code zylos.security} prefix.
 *
 * <p>All fields are mandatory unless documented otherwise; validation runs at
 * context startup so misconfiguration fails fast.
 *
 * @param issuerUri        exact {@code iss} value the realm publishes; tokens with a
 *                         different issuer are rejected with HTTP 401
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
    @NotBlank String expectedAudience,
    Duration clockSkew,
    JwksCacheProperties jwksCache,
    ActorChainsProperties actorChains,
    OpaProperties opa) {

    public ZylosSecurityProperties {
        if (clockSkew == null) {
            clockSkew = Duration.ofSeconds(30);
        }

        if (jwksCache == null) {
            jwksCache = new JwksCacheProperties(null, null);
        }

        if (actorChains == null) {
            actorChains = new ActorChainsProperties(null, null);
        }

        if (opa == null) {
            opa = new OpaProperties(null, null, null);
        }
    }

    /**
     * JWKS cache settings. The cache is a Caffeine-backed Spring {@link
     * org.springframework.cache.Cache} handed to {@code NimbusJwtDecoder}.
     */
    public record JwksCacheProperties(
        @Nullable Duration ttl, @Nullable @Positive Integer maxEntries) {
        public JwksCacheProperties {
            if (ttl == null) {
                ttl = Duration.ofHours(1);
            }

            if (maxEntries == null) {
                maxEntries = 16;
            }
        }
    }

    /**
     * Location of the actor-chains YAML.
     */
    public record ActorChainsProperties(@Nullable Boolean enabled, @Nullable String location) {
        public ActorChainsProperties {
            if (enabled == null) {
                enabled = true;
            }
            if (location == null) {
                location = "classpath:actor-chains.yaml";
            }
        }
    }

    /**
     * OPA endpoint and cache settings
     */
    public record OpaProperties(
        @Nullable URI endpoint,
        @Nullable Duration cacheTtl,
        @Nullable @Min(0) Integer cacheMaxSize) {
        public OpaProperties {
            if (cacheTtl == null) {
                cacheTtl = Duration.ofSeconds(30);
            }

            if (cacheMaxSize == null) {
                cacheMaxSize = 50_000;
            }
        }
    }
}
