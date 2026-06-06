package app.zylos.security.jwt;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import com.github.tomakehurst.wiremock.WireMockServer;

import app.zylos.security.autoconfigure.ZylosSecurityCommonAutoConfiguration;
import app.zylos.security.autoconfigure.ZylosSecurityReactiveAutoConfiguration;
import app.zylos.security.autoconfigure.ZylosSecurityServletAutoConfiguration;
import app.zylos.security.support.JwksTestSupport;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import reactor.test.StepVerifier;

/**
 * Behavioral coverage for the {@code jwk-set-uri} branch: keys are fetched from
 * the override endpoint (issuer-uri never dialed), and {@code iss} is still
 * enforced — a correctly-signed token with the wrong issuer is rejected.
 */
class JwkSetUriDecoderTest {

    private static final String ISSUER = "https://issuer.test/realms/zylos";
    private static final String WRONG_ISSUER = "https://evil.test/realms/zylos";
    private static final String AUDIENCE = "zylos-internal-hello";

    private final JwksTestSupport jwks = new JwksTestSupport();
    private WireMockServer keyServer;
    private String jwksUrl;

    @BeforeEach
    void startKeyServer() {
        keyServer = new WireMockServer(options().dynamicPort());
        keyServer.start();
        keyServer.stubFor(get(urlEqualTo("/certs"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(jwks.jwksJson())));
        jwksUrl = keyServer.baseUrl() + "/certs";
    }

    @AfterEach
    void stopKeyServer() {
        keyServer.stop();
    }

    @Test
    void servletJwkSetUriBranchFetchesKeysAndEnforcesIssuer() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ZylosSecurityCommonAutoConfiguration.class, ZylosSecurityServletAutoConfiguration.class))
                .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
                .withPropertyValues(
                        "zylos.security.issuer-uri=" + ISSUER,
                        "zylos.security.jwk-set-uri=" + jwksUrl,
                        "zylos.security.expected-audience=" + AUDIENCE,
                        "zylos.security.actor-chains.enabled=false")
                .run(context -> {
                    JwtDecoder decoder = context.getBean(JwtDecoder.class);

                    assertThat(decoder.decode(jwks.mint(ISSUER, AUDIENCE)).getSubject())
                            .isEqualTo("test-subject");

                    String token = jwks.mint(WRONG_ISSUER, AUDIENCE);
                    assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtValidationException.class);
                });
    }

    @Test
    void reactiveJwkSetUriBranchFetchesKeysAndEnforcesIssuer() {
        new ReactiveWebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ZylosSecurityCommonAutoConfiguration.class, ZylosSecurityReactiveAutoConfiguration.class))
                .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
                .withPropertyValues(
                        "zylos.security.issuer-uri=" + ISSUER,
                        "zylos.security.jwk-set-uri=" + jwksUrl,
                        "zylos.security.expected-audience=" + AUDIENCE,
                        "zylos.security.actor-chains.enabled=false")
                .run(context -> {
                    ReactiveJwtDecoder decoder = context.getBean(ReactiveJwtDecoder.class);

                    StepVerifier.create(decoder.decode(jwks.mint(ISSUER, AUDIENCE)))
                            .expectNextCount(1)
                            .verifyComplete();

                    StepVerifier.create(decoder.decode(jwks.mint(WRONG_ISSUER, AUDIENCE)))
                            .expectError(JwtValidationException.class)
                            .verify();
                });
    }
}
