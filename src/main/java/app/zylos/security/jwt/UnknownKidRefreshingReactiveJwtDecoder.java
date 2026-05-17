package app.zylos.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import reactor.core.publisher.Mono;

/**
 * Reactive equivalent of {@link UnknownKidRefreshingJwtDecoder}.
 *
 * <p>Semantics are identical: catch a {@link BadJwtException} that looks
 * like a kid mismatch, evict the JWKS cache entry, and retry exactly once.
 * Reactor's {@code onErrorResume} carries the retry semantics that the
 * servlet path expresses with try/catch.
 */
public final class UnknownKidRefreshingReactiveJwtDecoder implements ReactiveJwtDecoder {

    private static final Logger log = LoggerFactory.getLogger(UnknownKidRefreshingReactiveJwtDecoder.class);

    private final ReactiveJwtDecoder inner;
    private final Cache jwksCache;
    private final String jwkSetUri;
    private final Counter refreshCounter;

    public UnknownKidRefreshingReactiveJwtDecoder(
            ReactiveJwtDecoder inner, Cache jwksCache, String jwkSetUri, MeterRegistry meterRegistry) {
        this.inner = inner;
        this.jwksCache = jwksCache;
        this.jwkSetUri = jwkSetUri;
        this.refreshCounter = Counter.builder("zylos_jwks_forced_refresh_total")
                .description("Number of JWKS cache evictions triggered by an unknown kid")
                .tag("decoder", "reactive")
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
    public Mono<Jwt> decode(String token) {
        return inner.decode(token).onErrorResume(BadJwtException.class, firstException -> {
            if (!looksLikeKidIssue(firstException)) {
                return Mono.error(firstException);
            }

            log.debug(
                    "Possible unknown kid detected ({}); evicting JWKS cache and retrying",
                    firstException.getMessage());
            jwksCache.evict(jwkSetUri);
            refreshCounter.increment();

            return inner.decode(token); // No further retry on second failure
        });
    }
}
