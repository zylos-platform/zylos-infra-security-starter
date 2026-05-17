package app.zylos.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class UnknownKidRefreshingJwtDecoderTest {

    private static final String JWK_SET_URI = "https://keycloak.zylos.local/realms/zylos/protocol/openid-connect/certs";
    private static final String TOKEN = "eyJ...test";

    private JwtDecoder inner;
    private Cache jwksCache;
    private MeterRegistry meterRegistry;
    private UnknownKidRefreshingJwtDecoder decoder;

    private static Jwt sampleJwt() {
        return Jwt.withTokenValue(TOKEN)
                .header("alg", "RS256")
                .header("kid", "new-key-1")
                .issuer("https://keycloak.zylos.local/realms/zylos")
                .subject("alice")
                .audience(List.of("zylos-internal-hello"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(900))
                .build();
    }

    @BeforeEach
    void setUp() {
        inner = mock(JwtDecoder.class);
        jwksCache = new ConcurrentMapCache("jwks");
        jwksCache.put(JWK_SET_URI, "cached-jwks-set"); // Simulate a populated cache
        meterRegistry = new SimpleMeterRegistry();
        decoder = new UnknownKidRefreshingJwtDecoder(inner, jwksCache, JWK_SET_URI, meterRegistry);
    }

    @Test
    void delegatesSuccessfulDecodeToInner() {
        Jwt expected = sampleJwt();
        when(inner.decode(TOKEN)).thenReturn(expected);

        Jwt actual = decoder.decode(TOKEN);

        assertThat(actual).isSameAs(expected);
        verify(inner, times(1)).decode(TOKEN);
        // Cache untouched on success.
        assertThat(jwksCache.get(JWK_SET_URI)).isNotNull();
    }

    @Test
    void evictsCacheAndRetriesOnUnknownKidError() {
        Jwt afterRefresh = sampleJwt();
        when(inner.decode(TOKEN))
                .thenThrow(new BadJwtException("Signed JWT rejected: No matching JWK found for kid 'new-key-1'"))
                .thenReturn(afterRefresh);

        Jwt result = decoder.decode(TOKEN);

        assertThat(result).isSameAs(afterRefresh);
        verify(inner, times(2)).decode(TOKEN);
        // Cache should have been evicted between calls.
        assertThat(jwksCache.get(JWK_SET_URI)).isNull();
        // Metric incremented.
        assertThat(meterRegistry
                        .counter("zylos_jwks_forced_refresh_total", "decoder", "servlet")
                        .count())
                .isEqualTo(1.0);
    }

    @Test
    void doesNotRetryOnNonKidError() {
        when(inner.decode(TOKEN)).thenThrow(new BadJwtException("Token expired"));

        assertThatThrownBy(() -> decoder.decode(TOKEN))
                .isInstanceOf(BadJwtException.class)
                .hasMessageContaining("Token expired");

        verify(inner, atMostOnce()).decode(TOKEN);
        assertThat(jwksCache.get(JWK_SET_URI)).isNotNull(); // Cache untouched.
    }

    @Test
    void doesNotRetryMultipleTimesOnPersistentFailure() {
        when(inner.decode(TOKEN))
                .thenThrow(new BadJwtException("No matching JWK found for kid 'unknown'"))
                .thenThrow(new BadJwtException("No matching JWK found for kid 'unknown'"));

        assertThatThrownBy(() -> decoder.decode(TOKEN)).isInstanceOf(BadJwtException.class);

        verify(inner, times(2)).decode(TOKEN); // Exactly one retry, no further.
    }

    @Test
    void retriesWhenMessageMentionsRemoteJwkRetrieval() {
        Jwt jwt = sampleJwt();
        when(inner.decode(TOKEN))
                .thenThrow(new BadJwtException("Couldn't retrieve remote JWK set"))
                .thenReturn(jwt);

        Jwt result = decoder.decode(TOKEN);

        assertThat(result).isSameAs(jwt);
        verify(inner, times(2)).decode(TOKEN);
    }

    @Test
    void propagatesUnrelatedJwtExceptions() {
        when(inner.decode(anyString())).thenThrow(new JwtException("Malformed token"));

        assertThatThrownBy(() -> decoder.decode(TOKEN))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("Malformed token");
    }
}
