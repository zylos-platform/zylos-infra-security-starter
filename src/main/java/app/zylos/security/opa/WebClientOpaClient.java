package app.zylos.security.opa;

import java.net.URI;
import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.ResolvableType;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.netty.channel.ChannelOption;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

/**
 * Reactive-stack {@link ReactiveOpaClient} backed by Spring's {@link WebClient}.
 *
 */
public final class WebClientOpaClient implements ReactiveOpaClient {

    private static final Logger log = LoggerFactory.getLogger(WebClientOpaClient.class);

    private final WebClient webClient;
    private final Timer evaluationTimer;
    private final Timer evaluationFailureTimer;

    public WebClientOpaClient(WebClient webClient, MeterRegistry meterRegistry) {
        this.webClient = webClient;

        this.evaluationTimer = Timer.builder("zylos_opa_decision_duration_seconds")
                .description("OPA decision call duration (success)")
                .tag("outcome", "success")
                .publishPercentileHistogram()
                .register(meterRegistry);

        this.evaluationFailureTimer = Timer.builder("zylos_opa_decision_duration_seconds")
                .description("OPA decision call duration (failure)")
                .tag("outcome", "failure")
                .publishPercentileHistogram()
                .register(meterRegistry);
    }

    public static WebClientOpaClient create(
            URI endpoint, Duration connectTimeout, Duration readTimeout, MeterRegistry meterRegistry) {

        ConnectionProvider provider = ConnectionProvider.builder("zylos-opa")
                .maxConnections(50)
                .pendingAcquireTimeout(Duration.ofSeconds(1))
                .build();

        HttpClient http = HttpClient.create(provider)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, (int) connectTimeout.toMillis())
                .responseTimeout(readTimeout);

        WebClient webClient = WebClient.builder()
                .baseUrl(endpoint.toString())
                .clientConnector(new ReactorClientHttpConnector(http))
                .build();

        return new WebClientOpaClient(webClient, meterRegistry);
    }

    private static String normalizePath(String policyPath) {
        String trimmed = policyPath.startsWith("/") ? policyPath.substring(1) : policyPath;
        return "/v1/data/" + trimmed;
    }

    @Override
    public <T> Mono<T> evaluate(String policyPath, Object input, Class<T> resultType) {
        String dataPath = normalizePath(policyPath);
        OpaDecisionRequest body = OpaDecisionRequest.of(input);

        return Mono.defer(() -> {
            Timer.Sample sample = Timer.start();

            return webClient
                    .post()
                    .uri(dataPath)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(envelopeType(resultType))
                    .map(DataApiEnvelope::result) // Extract T from envelope
                    .doOnSuccess(_ -> sample.stop(evaluationTimer))
                    .onErrorMap(WebClientResponseException.class, e -> {
                        sample.stop(evaluationFailureTimer);
                        log.debug(
                                "OPA HTTP error path={} status={}",
                                policyPath,
                                e.getStatusCode().value());
                        return new OpaDecisionException(
                                "OPA returned " + e.getStatusCode() + ": " + e.getMessage(),
                                e.getStatusCode().value());
                    })
                    .onErrorMap(e -> !(e instanceof OpaDecisionException), e -> {
                        sample.stop(evaluationFailureTimer);
                        log.warn("OPA call failed path={} cause={}", policyPath, e.getMessage());
                        return new OpaDecisionException("OPA call failed: " + e.getMessage(), e);
                    });
        });
    }

    private <T> ParameterizedTypeReference<DataApiEnvelope<T>> envelopeType(Class<T> resultType) {
        return ParameterizedTypeReference.forType(ResolvableType.forClassWithGenerics(DataApiEnvelope.class, resultType)
                .getType());
    }

    private record DataApiEnvelope<T>(T result) {}
}
