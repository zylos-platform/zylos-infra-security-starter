package app.zylos.security.opa;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;

import org.jspecify.annotations.Nullable;

import com.github.benmanes.caffeine.cache.AsyncCache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import reactor.core.publisher.Mono;

public final class ReactiveCachingOpaClient implements ReactiveOpaClient {

    private final ReactiveOpaClient delegate;
    private final AsyncCache<CacheKey, CachedResult<?>> cache;

    public ReactiveCachingOpaClient(
            ReactiveOpaClient delegate, Duration ttl, int maxSize, MeterRegistry meterRegistry) {
        this.delegate = delegate;

        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(ttl)
                .maximumSize(maxSize)
                .recordStats()
                .buildAsync();

        CaffeineCacheMetrics.monitor(meterRegistry, this.cache.synchronous(), "zylos_opa_decision_cache");
    }

    @Override
    public <T> Mono<T> evaluate(String policyPath, Object input, Class<T> resultType) {
        CacheKey key = new CacheKey(policyPath, resultType, input);

        CompletableFuture<CachedResult<?>> futureResult = cache.get(
                key,
                (_, _) -> delegate.evaluate(policyPath, input, resultType)
                        .<CachedResult<?>>map(result -> new CachedResult<>(result, null))
                        .switchIfEmpty(Mono.just(new CachedResult<>(null, null)))
                        .onErrorResume(OpaDecisionException.class, e -> Mono.just(new CachedResult<>(null, e)))
                        .toFuture());

        return Mono.fromFuture(futureResult).flatMap(cached -> {
            if (cached.exception() != null) {
                return Mono.error(cached.exception());
            }
            if (cached.value() == null) {
                return Mono.empty();
            }
            return Mono.just(resultType.cast(cached.value()));
        });
    }

    public long size() {
        cache.synchronous().cleanUp();
        return cache.synchronous().estimatedSize();
    }

    public void invalidateAll() {
        cache.synchronous().invalidateAll();
    }

    private record CacheKey(String policyPath, Class<?> resultType, Object input) {}

    private record CachedResult<T>(
            @Nullable T value, @Nullable OpaDecisionException exception) {}
}
