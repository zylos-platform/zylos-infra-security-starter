package app.zylos.security.metrics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class MeteredJwtDecoderTest {

    private JwtDecoder inner;
    private MeterRegistry meterRegistry;
    private MeteredJwtDecoder decoder;

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
        inner = mock(JwtDecoder.class);
        meterRegistry = new SimpleMeterRegistry();
        decoder = new MeteredJwtDecoder(inner, meterRegistry);
    }

    @Test
    void successIncrementsSuccessCounterAndTimer() {
        Jwt jwt = sampleJwt();
        when(inner.decode("token")).thenReturn(jwt);

        Jwt result = decoder.decode("token");

        assertThat(result).isSameAs(jwt);
        assertThat(meterRegistry
                        .counter("zylos_jwt_validation_total", "outcome", "success", "reason", "ok")
                        .count())
                .isEqualTo(1.0);
        assertThat(meterRegistry
                        .timer("zylos_jwt_validation_duration_seconds", "outcome", "success")
                        .count())
                .isEqualTo(1L);
    }

    @Test
    void expiredFailureIsClassifiedAndCounted() {
        List<OAuth2Error> errors = List.of(new OAuth2Error("invalid_token", "Jwt expired at 2024-01-01", null));
        JwtValidationException expiredException = new JwtValidationException("Jwt expired at 2024-01-01", errors);

        when(inner.decode("token")).thenThrow(expiredException);

        assertThatThrownBy(() -> decoder.decode("token")).isInstanceOf(JwtValidationException.class);

        assertThat(meterRegistry
                        .counter(
                                "zylos_jwt_validation_total",
                                "outcome",
                                "failure",
                                "reason",
                                JwtFailureClassifier.FailureReason.EXPIRED.getTagValue())
                        .count())
                .isEqualTo(1.0);
        assertThat(meterRegistry
                        .timer(
                                "zylos_jwt_validation_duration_seconds",
                                "outcome",
                                "failure",
                                "reason",
                                JwtFailureClassifier.FailureReason.EXPIRED.getTagValue())
                        .count())
                .isEqualTo(1L);
    }

    @Test
    void invalidAudienceFailureIsClassifiedAndCounted() {
        List<OAuth2Error> errors =
                List.of(new OAuth2Error("invalid_audience", "invalid_audience: missing 'zylos-cart'", null));
        JwtValidationException expiredException =
                new JwtValidationException("invalid_audience: missing 'zylos-cart'", errors);

        when(inner.decode("token")).thenThrow(expiredException);

        assertThatThrownBy(() -> decoder.decode("token")).isInstanceOf(JwtValidationException.class);

        assertThat(meterRegistry
                        .counter(
                                "zylos_jwt_validation_total",
                                "outcome",
                                "failure",
                                "reason",
                                JwtFailureClassifier.FailureReason.INVALID_AUDIENCE.getTagValue())
                        .count())
                .isEqualTo(1.0);
    }

    @Test
    void invalidSignatureFailureIsClassifiedAndCounted() {
        when(inner.decode("token")).thenThrow(new BadJwtException("Signed JWT rejected: Invalid signature"));

        assertThatThrownBy(() -> decoder.decode("token")).isInstanceOf(BadJwtException.class);

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
