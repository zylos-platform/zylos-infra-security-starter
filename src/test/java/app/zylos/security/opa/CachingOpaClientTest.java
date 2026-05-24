package app.zylos.security.opa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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

class CachingOpaClientTest {

    private OpaClient inner;
    private CachingOpaClient cache;
    private MeterRegistry meterRegistry;

    @BeforeEach
    void setUp() {
        inner = mock(OpaClient.class);
        meterRegistry = new SimpleMeterRegistry();
        cache = new CachingOpaClient(inner, Duration.ofSeconds(30), 1000, meterRegistry);
    }

    @Test
    void firstCallHitsInner_secondCallHitsCache() {
        OpaDecisionResponse allow = new OpaDecisionResponse(true, List.of("ok"), null);
        when(inner.evaluate(eq("zylos/p"), any(), eq(OpaDecisionResponse.class)))
                .thenReturn(allow);

        OpaDecisionResponse first = cache.evaluate("zylos/p", Map.of("k", "v"), OpaDecisionResponse.class);
        OpaDecisionResponse second = cache.evaluate("zylos/p", Map.of("k", "v"), OpaDecisionResponse.class);

        assertThat(first).isSameAs(allow);
        assertThat(second).isSameAs(allow);
        verify(inner, times(1)).evaluate(eq("zylos/p"), any(), eq(OpaDecisionResponse.class));

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
        when(inner.evaluate(eq("zylos/p"), eq(Map.of("k", "a")), eq(OpaDecisionResponse.class)))
                .thenReturn(responseA);
        when(inner.evaluate(eq("zylos/p"), eq(Map.of("k", "b")), eq(OpaDecisionResponse.class)))
                .thenReturn(responseB);

        OpaDecisionResponse a = cache.evaluate("zylos/p", Map.of("k", "a"), OpaDecisionResponse.class);
        OpaDecisionResponse b = cache.evaluate("zylos/p", Map.of("k", "b"), OpaDecisionResponse.class);

        assertThat(a.allow()).isTrue();
        assertThat(b.allow()).isFalse();
        verify(inner, times(2)).evaluate(eq("zylos/p"), any(), eq(OpaDecisionResponse.class));
    }

    @Test
    void exceptionsAreCachedAsNegativeResults() {
        OpaDecisionException error = new OpaDecisionException("opa down");
        when(inner.evaluate(any(), any(), any())).thenThrow(error);

        assertThatThrownBy(() -> cache.evaluate("zylos/p", Map.of(), OpaDecisionResponse.class))
                .isSameAs(error);
        assertThatThrownBy(() -> cache.evaluate("zylos/p", Map.of(), OpaDecisionResponse.class))
                .isSameAs(error);

        verify(inner, times(1)).evaluate(any(), any(), any());
    }

    @Test
    void differentResultTypesAreNotMixed() {
        when(inner.evaluate(eq("zylos/p"), eq(Map.of()), eq(OpaDecisionResponse.class)))
                .thenReturn(new OpaDecisionResponse(true, null, null));
        when(inner.evaluate(eq("zylos/p"), eq(Map.of()), eq(Map.class))).thenReturn(Map.of("custom", "shape"));

        cache.evaluate("zylos/p", Map.of(), OpaDecisionResponse.class);
        cache.evaluate("zylos/p", Map.of(), Map.class);

        // Same path + input but different result types — should be two cache entries
        verify(inner, times(1)).evaluate(eq("zylos/p"), eq(Map.of()), eq(OpaDecisionResponse.class));
        verify(inner, times(1)).evaluate(eq("zylos/p"), eq(Map.of()), eq(Map.class));
        assertThat(cache.size()).isEqualTo(2);
    }

    @Test
    void invalidateAllClearsCache() {
        when(inner.evaluate(any(), any(), any())).thenReturn(new OpaDecisionResponse(true, null, null));
        cache.evaluate("zylos/p", Map.of(), OpaDecisionResponse.class);

        cache.invalidateAll();

        assertThat(cache.size()).isZero();
    }

    @Test
    void checkShortcutCachesAcrossCalls() {
        when(inner.evaluate(any(), any(), eq(OpaDecisionResponse.class)))
                .thenReturn(new OpaDecisionResponse(true, null, null));

        cache.check("zylos/p", Map.of());
        cache.check("zylos/p", Map.of());

        verify(inner, times(1)).evaluate(any(), any(), eq(OpaDecisionResponse.class));
    }
}
