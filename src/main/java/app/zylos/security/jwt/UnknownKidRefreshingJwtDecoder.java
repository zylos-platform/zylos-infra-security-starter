package app.zylos.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Decorating {@link JwtDecoder} that forces a JWKS cache refresh when an
 * inbound token carries a {@code kid} the cache doesn't know about.
 *
 * <p>The JWKS cache TTL is 1 hour. Without this
 * decorator, a freshly-rotated signing key would not be picked up until the
 * cache expires — causing a 401 storm during the rotation window. This
 * decorator catches signature-resolution failures from the inner decoder,
 * evicts the JWK Set URI from the cache (forcing the next call to refresh
 * from the upstream JWKS endpoint), and retries the decode exactly once.
 *
 * <p>Single-flight is provided by Nimbus's internal locking on the decoder
 * instance; concurrent unknown-kid requests within the same JVM trigger a
 * single upstream fetch.
 *
 * <p>Unknown-kid detection is heuristic on the BadJwtException message text.
 * Spring Security wraps Nimbus errors with messages.
 * A future improvement could replace this with a pre-decode kid extraction.
 */
public final class UnknownKidRefreshingJwtDecoder implements JwtDecoder {

    private static final Logger log = LoggerFactory.getLogger(UnknownKidRefreshingJwtDecoder.class);

    private final JwtDecoder inner;
    private final Cache jwksCache;
    private final String jwkSetUri;
    private final Counter refreshCounter;

    public UnknownKidRefreshingJwtDecoder(
            JwtDecoder inner, Cache jwksCache, String jwkSetUri, MeterRegistry meterRegistry) {
        this.inner = inner;
        this.jwksCache = jwksCache;
        this.jwkSetUri = jwkSetUri;
        this.refreshCounter = Counter.builder("zylos_jwks_forced_refresh_total")
                .description("Number of JWKS cache evictions triggered by an unknown kid")
                .tag("decoder", "servlet")
                .register(meterRegistry);
    }

    private static boolean looksLikeKidIssue(BadJwtException e) {
        String message = e.getMessage();

        if (message == null) {
            return false;
        }

        return message.contains("matching key")
                || message.contains("matching JWK")
                || message.contains("Couldn't retrieve remote JWK set")
                || message.contains("kid");
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            return inner.decode(token);

        } catch (BadJwtException firstException) {
            if (!looksLikeKidIssue(firstException)) {
                throw firstException;
            }

            log.debug(
                    "Possible unknown kid detected ({}); evicting JWKS cache and retrying",
                    firstException.getMessage());
            jwksCache.evict(jwkSetUri);
            refreshCounter.increment();

            return inner.decode(token); // Don't recurse; the token is genuinely invalid.
        }
    }
}
