package app.zylos.security.metrics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class MeteredReactiveJwtDecoderTest {

    private ReactiveJwtDecoder inner;
    private MeterRegistry meterRegistry;
    private MeteredReactiveJwtDecoder decoder;

    private static Jwt sampleJwt() {
        return Jwt.withTokenValue("test")
                .header("alg", "RS256")
                .subject("alice")
                .audience(List.of("zylos-internal-hello"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(900))
                .build();
    }

    @BeforeEach
    void setUp() {
        inner = mock(ReactiveJwtDecoder.class);
        meterRegistry = new SimpleMeterRegistry();
        decoder = new MeteredReactiveJwtDecoder(inner, meterRegistry);
    }

    @Test
    void successIncrementsSuccessCounter() {
        Jwt jwt = sampleJwt();
        when(inner.decode("token")).thenReturn(Mono.just(jwt));

        StepVerifier.create(decoder.decode("token")).expectNext(jwt).verifyComplete();

        assertThat(meterRegistry
                        .counter("zylos_jwt_validation_total", "outcome", "success", "reason", "ok")
                        .count())
                .isEqualTo(1.0);
    }

    @Test
    void failureIncrementsFailureCounterWithClassifiedReason() {
        when(inner.decode("token"))
                .thenReturn(Mono.error(new BadJwtException("Signed JWT rejected: Invalid signature")));

        StepVerifier.create(decoder.decode("token"))
                .expectError(BadJwtException.class)
                .verify();

        assertThat(meterRegistry
                        .counter(
                                "zylos_jwt_validation_total",
                                "outcome",
                                "failure",
                                "reason",
                                JwtFailureClassifier.FailureReason.INVALID_SIGNATURE.getTagValue())
                        .count())
                .isEqualTo(1.0);
    }
}
