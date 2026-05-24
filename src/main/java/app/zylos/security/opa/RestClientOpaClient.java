package app.zylos.security.opa;

import java.net.URI;
import java.time.Duration;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.ResolvableType;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

/**
 * Servlet-stack {@link OpaClient} backed by Spring's {@link RestClient}.
 *
 * <p>Configured with a dedicated {@link ClientHttpRequestFactory} so the OPA
 * client's tight timeouts don't leak into the service's general-purpose
 * RestClient(s). {@link ClientHttpRequestFactoryBuilder#detect()} picks
 * Apache HttpClient5 when on the classpath (which it is via Spring Boot 4's
 * transitive dependencies on most services), else falls back to the JDK
 * HttpClient.
 *
 * <p>Configure a 1-second read timeout — generous headroom for the SLO that
 * still ensures fast-fail behavior when OPA is genuinely unhealthy.
 */
public final class RestClientOpaClient implements OpaClient {

    private static final Logger log = LoggerFactory.getLogger(RestClientOpaClient.class);

    private final RestClient restClient;
    private final Timer evaluationTimer;
    private final Timer evaluationFailureTimer;

    public RestClientOpaClient(RestClient restClient, MeterRegistry meterRegistry) {
        this.restClient = restClient;

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

    /**
     * Convenience factory using the package's standard timeouts.
     *
     * @param endpoint       base OPA URL (e.g., {@code http://opa.opa-system.svc.cluster.local:8181})
     * @param connectTimeout connect timeout (sub-second recommended)
     * @param readTimeout    read timeout (≤ 2s recommended)
     * @param meterRegistry  where to register metrics
     */
    public static RestClientOpaClient create(
            URI endpoint, Duration connectTimeout, Duration readTimeout, MeterRegistry meterRegistry) {

        HttpClientSettings settings =
                HttpClientSettings.defaults().withConnectTimeout(connectTimeout).withReadTimeout(readTimeout);

        ClientHttpRequestFactory factory =
                ClientHttpRequestFactoryBuilder.detect().build(settings);

        RestClient restClient = RestClient.builder()
                .baseUrl(endpoint.toString())
                .requestFactory(factory)
                .build();

        return new RestClientOpaClient(restClient, meterRegistry);
    }

    private static String normalizePath(String policyPath) {
        String trimmed = policyPath.startsWith("/") ? policyPath.substring(1) : policyPath;
        return "/v1/data/" + trimmed;
    }

    @Override
    public <T> @Nullable T evaluate(String policyPath, Object input, Class<T> resultType) {
        Timer.Sample sample = Timer.start();

        try {
            T result = doEvaluate(policyPath, input, resultType);
            sample.stop(evaluationTimer);
            return result;

        } catch (OpaDecisionException e) {
            sample.stop(evaluationFailureTimer);
            throw e;

        } catch (Exception e) {
            sample.stop(evaluationFailureTimer);
            throw new OpaDecisionException("OPA decision failed: " + e.getMessage(), e);
        }
    }

    private <T> @Nullable T doEvaluate(String policyPath, Object input, Class<T> resultType) {
        String dataPath = normalizePath(policyPath);
        OpaDecisionRequest body = OpaDecisionRequest.of(input);

        try {
            DataApiEnvelope<T> envelope = restClient
                    .post()
                    .uri(_ -> UriComponentsBuilder.fromPath(dataPath).build().toUri())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(envelopeType(resultType));
            return envelope == null ? null : envelope.result();

        } catch (HttpClientErrorException e) {
            log.debug(
                    "OPA client error path={} status={}",
                    policyPath,
                    e.getStatusCode().value());
            throw new OpaDecisionException(
                    "OPA returned client error: " + e.getStatusCode(),
                    e.getStatusCode().value());

        } catch (HttpServerErrorException e) {
            log.warn(
                    "OPA server error path={} status={}",
                    policyPath,
                    e.getStatusCode().value());
            throw new OpaDecisionException(
                    "OPA returned server error: " + e.getStatusCode(),
                    e.getStatusCode().value());

        } catch (ResourceAccessException e) {
            log.warn("OPA unreachable path={} cause={}", policyPath, e.getMessage());
            throw new OpaDecisionException("OPA unreachable: " + e.getMessage(), e);
        }
    }

    private <T> ParameterizedTypeReference<DataApiEnvelope<T>> envelopeType(Class<T> resultType) {
        return ParameterizedTypeReference.forType(ResolvableType.forClassWithGenerics(DataApiEnvelope.class, resultType)
                .getType());
    }

    private record DataApiEnvelope<T>(T result) {}
}
