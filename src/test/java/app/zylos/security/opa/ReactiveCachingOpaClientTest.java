package app.zylos.security.opa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class ReactiveCachingOpaClientTest {

    private ReactiveOpaClient inner;
    private ReactiveCachingOpaClient cache;
    private MeterRegistry meterRegistry;

    @BeforeEach
    void setUp() {
        inner = mock(ReactiveOpaClient.class);
        meterRegistry = new SimpleMeterRegistry();
        cache = new ReactiveCachingOpaClient(inner, Duration.ofSeconds(30), 1000, meterRegistry);
    }

    @Test
    void firstCallHitsInner_secondCallHitsCache() {
        OpaDecisionResponse allow = new OpaDecisionResponse(true, List.of("ok"), null);
        when(inner.evaluate(eq("zylos/p"), any(), eq(OpaDecisionResponse.class)))
                .thenReturn(Mono.just(allow));

        Map<String, Object> input = Map.of("k", "v");

        // First call - triggers the mock
        StepVerifier.create(cache.evaluate("zylos/p", input, OpaDecisionResponse.class))
                .assertNext(response -> assertThat(response).isSameAs(allow))
                .verifyComplete();

        // Second call - should hit the cache immediately
        StepVerifier.create(cache.evaluate("zylos/p", input, OpaDecisionResponse.class))
                .assertNext(response -> assertThat(response).isSameAs(allow))
                .verifyComplete();

        verify(inner, times(1)).evaluate(eq("zylos/p"), any(), eq(OpaDecisionResponse.class));

        // Validate Micrometer metrics
        assertThat(meterRegistry
                        .get("cache.gets")
                        .tag("cache", "zylos_opa_decision_cache")
                        .tag("result", "hit")
                        .functionCounter()
                        .count())
                .isEqualTo(1.0);

        assertThat(meterRegistry
                        .get("cache.gets")
                        .tag("cache", "zylos_opa_decision_cache")
                        .tag("result", "miss")
                        .functionCounter()
                        .count())
                .isEqualTo(1.0);
    }

    @Test
    void differentInputsResultInDistinctCacheEntries() {
        OpaDecisionResponse responseA = new OpaDecisionResponse(true, null, null);
        OpaDecisionResponse responseB = new OpaDecisionResponse(false, null, null);

        Map<String, Object> inputA = Map.of("k", "a");
        Map<String, Object> inputB = Map.of("k", "b");

        when(inner.evaluate(eq("zylos/p"), eq(inputA), eq(OpaDecisionResponse.class)))
                .thenReturn(Mono.just(responseA));
        when(inner.evaluate(eq("zylos/p"), eq(inputB), eq(OpaDecisionResponse.class)))
                .thenReturn(Mono.just(responseB));

        StepVerifier.create(cache.evaluate("zylos/p", inputA, OpaDecisionResponse.class))
                .assertNext(response -> assertThat(response.allow()).isTrue())
                .verifyComplete();

        StepVerifier.create(cache.evaluate("zylos/p", inputB, OpaDecisionResponse.class))
                .assertNext(response -> assertThat(response.allow()).isFalse())
                .verifyComplete();

        verify(inner, times(2)).evaluate(eq("zylos/p"), any(), eq(OpaDecisionResponse.class));
    }

    @Test
    void exceptionsAreCachedAsNegativeResults() {
        OpaDecisionException error = new OpaDecisionException("opa down", 500);
        when(inner.evaluate(any(), any(), any())).thenReturn(Mono.error(error));

        Map<String, Object> input = Map.of();

        // First call: calls inner, receives error, caches the error
        StepVerifier.create(cache.evaluate("zylos/p", input, OpaDecisionResponse.class))
                .expectErrorMatches(e -> e == error)
                .verify();

        // Second call: retrieves the exact same exception from cache, skips inner
        StepVerifier.create(cache.evaluate("zylos/p", input, OpaDecisionResponse.class))
                .expectErrorMatches(e -> e == error)
                .verify();

        verify(inner, times(1)).evaluate(any(), any(), any());
    }

    @Test
    void differentResultTypesAreNotMixed() {
        Map<String, Object> input = Map.of();

        when(inner.evaluate(eq("zylos/p"), eq(input), eq(OpaDecisionResponse.class)))
                .thenReturn(Mono.just(new OpaDecisionResponse(true, null, null)));
        when(inner.evaluate(eq("zylos/p"), eq(input), eq(Map.class))).thenReturn(Mono.just(Map.of("custom", "shape")));

        StepVerifier.create(cache.evaluate("zylos/p", input, OpaDecisionResponse.class))
                .expectNextCount(1)
                .verifyComplete();

        StepVerifier.create(cache.evaluate("zylos/p", input, Map.class))
                .expectNextCount(1)
                .verifyComplete();

        // Same path + input but different result types — should be two cache entries
        verify(inner, times(1)).evaluate(eq("zylos/p"), eq(input), eq(OpaDecisionResponse.class));
        verify(inner, times(1)).evaluate(eq("zylos/p"), eq(input), eq(Map.class));
        assertThat(cache.size()).isEqualTo(2);
    }

    @Test
    void invalidateAllClearsCache() {
        Map<String, Object> input = Map.of();

        when(inner.evaluate(any(), any(), any())).thenReturn(Mono.just(new OpaDecisionResponse(true, null, null)));

        StepVerifier.create(cache.evaluate("zylos/p", input, OpaDecisionResponse.class))
                .expectNextCount(1)
                .verifyComplete();

        cache.invalidateAll();

        assertThat(cache.size()).isZero();
    }

    @Test
    void checkShortcutCachesAcrossCalls() {
        when(inner.evaluate(any(), any(), eq(OpaDecisionResponse.class)))
                .thenReturn(Mono.just(new OpaDecisionResponse(true, null, null)));

        Map<String, Object> input = Map.of();

        StepVerifier.create(cache.check("zylos/p", input)).expectNext(true).verifyComplete();

        StepVerifier.create(cache.check("zylos/p", input)).expectNext(true).verifyComplete();

        verify(inner, times(1)).evaluate(any(), any(), eq(OpaDecisionResponse.class));
    }
}
