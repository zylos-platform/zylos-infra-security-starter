package app.zylos.security.opa;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class RestClientOpaClientTest {

    private static WireMockServer wireMock;
    private RestClientOpaClient client;
    private MeterRegistry meterRegistry;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
    }

    @AfterAll
    static void stopWireMock() {
        wireMock.stop();
    }

    @BeforeEach
    void setUp() {
        wireMock.resetAll();
        meterRegistry = new SimpleMeterRegistry();
        client = RestClientOpaClient.create(
                URI.create(wireMock.baseUrl()), Duration.ofMillis(500), Duration.ofSeconds(1), meterRegistry);
    }

    @Test
    void returnsParsedResponseForAllowDecision() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/cart/allow"))
                .withRequestBody(equalToJson("{\"input\":{\"action\":\"read\"}}"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"result\":{\"allow\":true,\"reasons\":[\"role-customer\"]}}")));

        OpaDecisionResponse response =
                client.evaluate("zylos/cart/allow", Map.of("action", "read"), OpaDecisionResponse.class);

        assertThat(response).isNotNull();
        assertThat(response.allow()).isTrue();
        assertThat(response.reasons()).containsExactly("role-customer");
    }

    @Test
    void returnsParsedResponseForDenyDecision() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/cart/allow"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"result\":{\"allow\":false,\"reasons\":[\"role-anonymous\"]}}")));

        OpaDecisionResponse response = client.evaluate("zylos/cart/allow", Map.of(), OpaDecisionResponse.class);

        assertThat(response).isNotNull();
        assertThat(response.allow()).isFalse();
    }

    @Test
    void checkShortcutReturnsTrueOnAllow() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/policy"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"result\":{\"allow\":true}}")));

        assertThat(client.check("zylos/policy", Map.of())).isTrue();
    }

    @Test
    void checkShortcutReturnsFalseOnDeny() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/policy"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"result\":{\"allow\":false}}")));

        assertThat(client.check("zylos/policy", Map.of())).isFalse();
    }

    @Test
    void leadingSlashInPolicyPathIsNormalized() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/cart"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"result\":{\"allow\":true}}")));

        assertThat(client.check("/zylos/cart", Map.of())).isTrue();
    }

    @Test
    void throwsOnHttpServerError() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/cart"))
                .willReturn(aResponse().withStatus(500).withBody("internal error")));

        Map<String, Object> input = Map.of();

        assertThatThrownBy(() -> client.evaluate("zylos/cart", input, OpaDecisionResponse.class))
                .isInstanceOf(OpaDecisionException.class)
                .hasMessageContaining("server error");
    }

    @Test
    void throwsOnHttpClientError() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/cart"))
                .willReturn(aResponse().withStatus(404).withBody("not found")));

        Map<String, Object> input = Map.of();

        assertThatThrownBy(() -> client.evaluate("zylos/cart", input, OpaDecisionResponse.class))
                .isInstanceOf(OpaDecisionException.class);
    }

    @Test
    void throwsOnReadTimeout() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/cart"))
                .willReturn(aResponse().withFixedDelay(2000).withBody("{\"result\":{\"allow\":true}}")));

        Map<String, Object> input = Map.of();

        // Client's read timeout is 1s; OPA stub holds for 2s.
        assertThatThrownBy(() -> client.evaluate("zylos/cart", input, OpaDecisionResponse.class))
                .isInstanceOf(OpaDecisionException.class);
    }

    @Test
    void successAndFailureTimersIncrement() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/ok"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"result\":{\"allow\":true}}")));
        wireMock.stubFor(
                post(urlEqualTo("/v1/data/zylos/err")).willReturn(aResponse().withStatus(500)));

        client.check("zylos/ok", Map.of());
        try {
            client.evaluate("zylos/err", Map.of(), OpaDecisionResponse.class);
        } catch (OpaDecisionException _) {
            // expected to fail; we're just verifying the timer increments
        }

        assertThat(meterRegistry
                        .timer("zylos_opa_decision_duration_seconds", "outcome", "success")
                        .count())
                .isEqualTo(1L);
        assertThat(meterRegistry
                        .timer("zylos_opa_decision_duration_seconds", "outcome", "failure")
                        .count())
                .isEqualTo(1L);
    }
}
