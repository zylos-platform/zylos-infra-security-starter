package app.zylos.security.metrics;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

/**
 * Servlet-stack {@link JwtDecoder} decorator that records duration and
 * outcome metrics for every JWT validation attempt.
 *
 * <p>Metrics published per architecture §16:
 * <ul>
 *   <li>{@code zylos_jwt_validation_total{outcome=success|failure,reason=...}}
 *       — counter; the {@code reason} tag is one of {@link JwtFailureClassifier}'s
 *       category constants on failure, or {@code "ok"} on success</li>
 *   <li>{@code zylos_jwt_validation_duration_seconds{outcome=success|failure}}
 *       — timer with percentile histogram; tracks end-to-end decoder
 *       latency including JWKS fetch on cache miss</li>
 * </ul>
 *
 * <p>Wraps the {@link app.zylos.security.jwt.UnknownKidRefreshingJwtDecoder}
 * already produced by the JWT autoconfiguration; sits at the outermost
 * layer of the decoder chain so duration includes refresh-and-retry on
 * unknown kid.
 */
public final class MeteredJwtDecoder implements JwtDecoder {

    private static final String COUNTER_NAME = "zylos_jwt_validation_total";
    private static final String TIMER_NAME = "zylos_jwt_validation_duration_seconds";

    private static final String TAG_OUTCOME = "outcome";
    private static final String TAG_REASON = "reason";
    private static final String OUTCOME_SUCCESS = "success";
    private static final String OUTCOME_FAILURE = "failure";
    private static final String REASON_OK = "ok";

    private final JwtDecoder inner;
    private final MeterRegistry meterRegistry;
    private final Timer successTimer;

    public MeteredJwtDecoder(JwtDecoder inner, MeterRegistry meterRegistry) {
        this.inner = inner;
        this.meterRegistry = meterRegistry;

        this.successTimer = Timer.builder(TIMER_NAME)
                .tag(TAG_OUTCOME, OUTCOME_SUCCESS)
                .publishPercentileHistogram()
                .register(meterRegistry);
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        Timer.Sample sample = Timer.start(meterRegistry);

        if (token.isBlank()) {
            recordFailure(sample, JwtFailureClassifier.FailureReason.MALFORMED.getTagValue());
            throw new IllegalArgumentException("Token cannot be blank");
        }

        try {
            Jwt jwt = inner.decode(token);
            sample.stop(successTimer);
            meterRegistry
                    .counter(COUNTER_NAME, TAG_OUTCOME, OUTCOME_SUCCESS, TAG_REASON, REASON_OK)
                    .increment();
            return jwt;

        } catch (JwtException e) {
            String reasonTag = JwtFailureClassifier.classify(e).getTagValue();
            recordFailure(sample, reasonTag);
            throw e;

        } catch (RuntimeException e) {
            recordFailure(sample, JwtFailureClassifier.FailureReason.OTHER.getTagValue());
            throw e;
        }
    }

    private void recordFailure(Timer.Sample sample, String reasonTag) {
        Timer failureTimer = Timer.builder(TIMER_NAME)
                .tag(TAG_OUTCOME, OUTCOME_FAILURE)
                .tag(TAG_REASON, reasonTag)
                .publishPercentileHistogram()
                .register(meterRegistry);

        sample.stop(failureTimer);

        meterRegistry
                .counter(COUNTER_NAME, TAG_OUTCOME, OUTCOME_FAILURE, TAG_REASON, reasonTag)
                .increment();
    }
}
