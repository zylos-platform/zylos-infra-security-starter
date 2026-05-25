package app.zylos.security.metrics;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import reactor.core.publisher.Mono;

/**
 * Reactive-stack equivalent of {@link MeteredJwtDecoder}. Same metric
 * names, same tags, same semantics.
 *
 * <p>Implemented using {@link Mono#doOnSuccess} / {@link Mono#doOnError}
 * to capture outcome; the start time is captured at subscription via
 * {@link Mono#defer} so concurrent subscriptions each measure their own
 * latency.
 */
public final class MeteredReactiveJwtDecoder implements ReactiveJwtDecoder {

    private static final String COUNTER_NAME = "zylos_jwt_validation_total";
    private static final String TIMER_NAME = "zylos_jwt_validation_duration_seconds";

    private static final String TAG_OUTCOME = "outcome";
    private static final String TAG_REASON = "reason";
    private static final String OUTCOME_SUCCESS = "success";
    private static final String OUTCOME_FAILURE = "failure";
    private static final String OUTCOME_CANCELLED = "cancelled";
    private static final String REASON_OK = "ok";

    private final ReactiveJwtDecoder inner;
    private final MeterRegistry meterRegistry;
    private final Timer successTimer;

    public MeteredReactiveJwtDecoder(ReactiveJwtDecoder inner, MeterRegistry meterRegistry) {
        this.inner = inner;
        this.meterRegistry = meterRegistry;

        this.successTimer = Timer.builder(TIMER_NAME)
                .tag(TAG_OUTCOME, OUTCOME_SUCCESS)
                .publishPercentileHistogram()
                .register(meterRegistry);
    }

    @Override
    public Mono<Jwt> decode(String token) {
        return Mono.defer(() -> {
            Timer.Sample sample = Timer.start(meterRegistry);

            if (token.isBlank()) {
                recordFailure(sample, JwtFailureClassifier.FailureReason.MALFORMED.getTagValue());
                return Mono.error(new IllegalArgumentException("Token cannot be blank"));
            }

            return inner.decode(token)
                    .doOnSuccess(_ -> {
                        sample.stop(successTimer);
                        meterRegistry
                                .counter(COUNTER_NAME, TAG_OUTCOME, OUTCOME_SUCCESS, TAG_REASON, REASON_OK)
                                .increment();
                    })
                    .doOnError(Throwable.class, e -> {
                        String reasonTag = (e instanceof JwtException jwtEx)
                                ? JwtFailureClassifier.classify(jwtEx).getTagValue()
                                : JwtFailureClassifier.FailureReason.OTHER.getTagValue();

                        recordFailure(sample, reasonTag);
                    })
                    .doOnCancel(() -> {
                        Timer cancelTimer = Timer.builder(TIMER_NAME)
                                .tag(TAG_OUTCOME, OUTCOME_CANCELLED)
                                .tag(TAG_REASON, JwtFailureClassifier.FailureReason.OTHER.getTagValue())
                                .publishPercentileHistogram()
                                .register(meterRegistry);

                        sample.stop(cancelTimer);
                        meterRegistry
                                .counter(
                                        COUNTER_NAME,
                                        TAG_OUTCOME,
                                        OUTCOME_CANCELLED,
                                        TAG_REASON,
                                        JwtFailureClassifier.FailureReason.OTHER.getTagValue())
                                .increment();
                    });
        });
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
