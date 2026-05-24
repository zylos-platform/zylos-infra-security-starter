package app.zylos.security.opa;

import java.time.Duration;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;

/**
 * Decorator wrapping an inner {@link OpaClient} with a Caffeine-backed
 * decision cache.
 *
 * <ul>
 *   <li>TTL: 30 seconds (long enough to absorb hot-path repetition; short
 *       enough to limit staleness window during policy bundle rollouts)</li>
 *   <li>Max entries: 50,000 (per Zylos service)</li>
 *   <li>Negative caching: cached failures (denials, exceptions) get the
 *       same TTL as positives — preventing stampedes against a denying
 *       policy or an unreachable OPA</li>
 * </ul>
 *
 * <p>Cache key is the tuple {@code (policyPath, resultType, input)} hashed
 * via the input object's {@link Object#hashCode}. Input objects MUST
 * implement a stable {@code equals}/{@code hashCode}; records satisfy this
 * by default. The caller is responsible for not mutating cache-keyed
 * inputs after passing them.
 *
 * <p>Exceptions thrown by the inner client are cached as terminal values
 * via {@link CachedResult#exception}; subsequent lookups within the TTL
 * re-throw the same exception without re-calling the inner. This is the
 * "negative caching" property.
 */
public final class CachingOpaClient implements OpaClient {

    private final OpaClient delegate;
    private final Cache<CacheKey, CachedResult<?>> cache;

    public CachingOpaClient(OpaClient delegate, Duration ttl, int maxSize, MeterRegistry meterRegistry) {
        this.delegate = delegate;

        Cache<CacheKey, CachedResult<?>> rawCache = Caffeine.newBuilder()
                .expireAfterWrite(ttl)
                .maximumSize(maxSize)
                .recordStats()
                .build();

        this.cache = CaffeineCacheMetrics.monitor(meterRegistry, rawCache, "zylos_opa_decision_cache");
    }

    @Override
    public <T> T evaluate(String policyPath, Object input, Class<T> resultType) {
        CacheKey key = new CacheKey(policyPath, resultType, input);

        // If the key is missing, ONE thread executes this block while others wait.
        CachedResult<?> cached = cache.get(key, _ -> {
            try {
                T result = delegate.evaluate(policyPath, input, resultType);
                return new CachedResult<>(result, null);

            } catch (OpaDecisionException e) {
                return new CachedResult<>(null, e);
            }
        });

        Objects.requireNonNull(cached, "Caffeine cache unexpectedly returned null");

        if (cached.exception() != null) {
            throw cached.exception();
        }

        return resultType.cast(cached.value());
    }

    public long size() {
        cache.cleanUp();
        return cache.estimatedSize();
    }

    public void invalidateAll() {
        cache.invalidateAll();
    }

    private record CacheKey(String policyPath, Class<?> resultType, Object input) {}

    private record CachedResult<T>(
            @Nullable T value, @Nullable OpaDecisionException exception) {}
}
