package app.zylos.security.opa;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

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
import reactor.test.StepVerifier;

class WebClientOpaClientTest {

    private static WireMockServer wireMock;
    private WebClientOpaClient client;

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
        MeterRegistry meterRegistry = new SimpleMeterRegistry();
        client = WebClientOpaClient.create(
                URI.create(wireMock.baseUrl()), Duration.ofMillis(500), Duration.ofSeconds(1), meterRegistry);
    }

    @Test
    void returnsParsedResponseForAllowDecision() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/cart/allow"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"result\":{\"allow\":true,\"reasons\":[\"role-customer\"]}}")));

        var responseMono = client.evaluate("zylos/cart/allow", Map.of(), OpaDecisionResponse.class);

        StepVerifier.create(responseMono)
                .assertNext(response -> {
                    assertThat(response).isNotNull();
                    assertThat(response.allow()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void throwsOnHttpServerError() {
        wireMock.stubFor(post(urlEqualTo("/v1/data/zylos/cart"))
                .willReturn(aResponse().withStatus(500).withBody("internal error")));

        Map<String, Object> input = Map.of();

        StepVerifier.create(client.evaluate("zylos/cart", input, OpaDecisionResponse.class))
                .expectError(OpaDecisionException.class)
                .verify();
    }

    @Test
    void checkShortcutReturnsFalseOnException() {
        wireMock.stubFor(
                post(urlEqualTo("/v1/data/zylos/cart")).willReturn(aResponse().withStatus(500)));

        Map<String, Object> input = Map.of();

        // check() must fail closed
        StepVerifier.create(client.check("zylos/cart", input)).expectNext(false).verifyComplete();
    }
}
