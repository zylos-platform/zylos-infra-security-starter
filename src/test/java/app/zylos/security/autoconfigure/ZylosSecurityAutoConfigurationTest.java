package app.zylos.security.autoconfigure;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.time.Duration;
import java.util.Collection;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.cache.Cache;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.util.ReflectionTestUtils;

import com.github.tomakehurst.wiremock.WireMockServer;

import app.zylos.security.jwt.AudienceValidator;
import app.zylos.security.jwt.UnknownKidRefreshingJwtDecoder;
import app.zylos.security.jwt.UnknownKidRefreshingReactiveJwtDecoder;
import app.zylos.security.jwt.ZylosJwtValidatorCustomizer;
import app.zylos.security.properties.ZylosSecurityProperties;

class ZylosSecurityAutoConfigurationTest {

    /**
     * WireMock-backed Keycloak OIDC discovery so NimbusJwtDecoder can resolve at startup.
     */
    private static WireMockServer wireMock;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        wireMock.stubFor(get(urlEqualTo("/realms/zylos/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                    {
                      "issuer": "%1$s/realms/zylos",
                      "jwks_uri": "%1$s/realms/zylos/protocol/openid-connect/certs",
                      "authorization_endpoint": "%1$s/realms/zylos/protocol/openid-connect/auth",
                      "token_endpoint": "%1$s/realms/zylos/protocol/openid-connect/token",
                      "response_types_supported": ["code"],
                      "subject_types_supported": ["public"],
                      "id_token_signing_alg_values_supported": ["RS256"]
                    }
                    """.formatted(wireMock.baseUrl()))));
        wireMock.stubFor(get(urlEqualTo("/realms/zylos/protocol/openid-connect/certs"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                    {
                      "keys": [
                        {
                          "kty": "RSA",
                          "kid": "rfc-test-key",
                          "use": "sig",
                          "alg": "RS256",
                          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                          "e": "AQAB"
                        }
                      ]
                    }
                    """)));
    }

    @AfterAll
    static void stopWireMock() {
        wireMock.stop();
    }

    private static String issuerUri() {
        return wireMock.baseUrl() + "/realms/zylos";
    }

    private static String[] minimalProperties() {
        return new String[] {
            "zylos.security.issuer-uri=" + issuerUri(), "zylos.security.expected-audience=zylos-internal-hello"
        };
    }

    @Test
    void servletAutoConfigurationWiresAllBeans() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ZylosSecurityCommonAutoConfiguration.class, ZylosSecurityServletAutoConfiguration.class))
                .withPropertyValues(minimalProperties())
                .run(context -> {
                    assertThat(context).hasSingleBean(ZylosSecurityProperties.class);
                    assertThat(context).hasSingleBean(Cache.class); // JWKS cache
                    assertThat(context).hasSingleBean(JwtDecoder.class);
                    assertThat(context.getBean(JwtDecoder.class)).isInstanceOf(UnknownKidRefreshingJwtDecoder.class);
                });
    }

    @Test
    void reactiveAutoConfigurationWiresAllBeans() {
        new ReactiveWebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ZylosSecurityCommonAutoConfiguration.class, ZylosSecurityReactiveAutoConfiguration.class))
                .withPropertyValues(minimalProperties())
                .run(context -> {
                    assertThat(context).hasSingleBean(ZylosSecurityProperties.class);
                    assertThat(context).hasSingleBean(Cache.class);
                    assertThat(context).hasSingleBean(ReactiveJwtDecoder.class);
                    assertThat(context.getBean(ReactiveJwtDecoder.class))
                            .isInstanceOf(UnknownKidRefreshingReactiveJwtDecoder.class);
                });
    }

    @Test
    void propertiesBindWithCorrectDefaults() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(ZylosSecurityCommonAutoConfiguration.class))
                .withPropertyValues(minimalProperties())
                .run(context -> {
                    ZylosSecurityProperties props = context.getBean(ZylosSecurityProperties.class);
                    assertThat(props.issuerUri()).isEqualTo(issuerUri());
                    assertThat(props.expectedAudience()).isEqualTo("zylos-internal-hello");
                    assertThat(props.clockSkew()).isEqualTo(Duration.ofSeconds(30));
                    assertThat(props.jwksCache().ttl()).isEqualTo(Duration.ofHours(1));
                    assertThat(props.jwksCache().maxEntries()).isEqualTo(16);
                });
    }

    @Test
    void propertiesOverrideDefaults() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(ZylosSecurityCommonAutoConfiguration.class))
                .withPropertyValues(
                        "zylos.security.issuer-uri=" + issuerUri(),
                        "zylos.security.expected-audience=zylos-internal-hello",
                        "zylos.security.clock-skew=10s",
                        "zylos.security.jwks-cache.ttl=2h",
                        "zylos.security.jwks-cache.max-entries=32")
                .run(context -> {
                    ZylosSecurityProperties props = context.getBean(ZylosSecurityProperties.class);
                    assertThat(props.clockSkew()).isEqualTo(Duration.ofSeconds(10));
                    assertThat(props.jwksCache().ttl()).isEqualTo(Duration.ofHours(2));
                    assertThat(props.jwksCache().maxEntries()).isEqualTo(32);
                });
    }

    @Test
    void servletValidatorChainIncludesExpectedValidators() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ZylosSecurityCommonAutoConfiguration.class, ZylosSecurityServletAutoConfiguration.class))
                .withPropertyValues(minimalProperties())
                .run(context -> {
                    assertThat(context).hasBean("zylosJwtValidator");

                    OAuth2TokenValidator<?> validator =
                            context.getBean("zylosJwtValidator", OAuth2TokenValidator.class);

                    assertThat(validator).isInstanceOf(DelegatingOAuth2TokenValidator.class);

                    @SuppressWarnings("unchecked")
                    Collection<OAuth2TokenValidator<Jwt>> delegates = (Collection<OAuth2TokenValidator<Jwt>>)
                            ReflectionTestUtils.getField(validator, "tokenValidators");

                    assertThat(delegates)
                            .isNotNull()
                            .hasSize(3)
                            .extracting(v -> v.getClass().getSimpleName())
                            .contains("JwtTimestampValidator", "JwtIssuerValidator", "AudienceValidator");
                });
    }

    @Test
    void reactiveValidatorChainIncludesExpectedValidators() {
        new ReactiveWebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ZylosSecurityCommonAutoConfiguration.class, ZylosSecurityReactiveAutoConfiguration.class))
                .withPropertyValues(minimalProperties())
                .run(context -> {
                    assertThat(context).hasBean("zylosReactiveJwtValidator");

                    OAuth2TokenValidator<?> validator =
                            context.getBean("zylosReactiveJwtValidator", OAuth2TokenValidator.class);

                    assertThat(validator).isInstanceOf(DelegatingOAuth2TokenValidator.class);

                    @SuppressWarnings("unchecked")
                    Collection<OAuth2TokenValidator<Jwt>> delegates = (Collection<OAuth2TokenValidator<Jwt>>)
                            ReflectionTestUtils.getField(validator, "tokenValidators");

                    assertThat(delegates)
                            .isNotNull()
                            .hasSize(3)
                            .extracting(v -> v.getClass().getSimpleName())
                            .contains("JwtTimestampValidator", "JwtIssuerValidator", "AudienceValidator");
                });
    }

    @Test
    void servletValidatorAppliesCustomizersCorrectly() {
        ZylosJwtValidatorCustomizer mockCustomizer = validators -> {
            @SuppressWarnings("unchecked")
            OAuth2TokenValidator<Jwt> customValidator = mock(OAuth2TokenValidator.class);
            validators.add(customValidator);
        };

        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ZylosSecurityCommonAutoConfiguration.class, ZylosSecurityServletAutoConfiguration.class))
                .withPropertyValues(minimalProperties())
                .withBean(ZylosJwtValidatorCustomizer.class, () -> mockCustomizer)
                .run(context -> {
                    OAuth2TokenValidator<?> validator =
                            context.getBean("zylosJwtValidator", OAuth2TokenValidator.class);

                    @SuppressWarnings("unchecked")
                    Collection<OAuth2TokenValidator<Jwt>> delegates = (Collection<OAuth2TokenValidator<Jwt>>)
                            ReflectionTestUtils.getField(validator, "tokenValidators");

                    assertThat(delegates).hasSize(4);
                });
    }

    @Test
    void reactiveValidatorAppliesCustomizersCorrectly() {
        ZylosJwtValidatorCustomizer mockCustomizer = validators -> {
            @SuppressWarnings("unchecked")
            OAuth2TokenValidator<Jwt> customValidator = mock(OAuth2TokenValidator.class);
            validators.add(customValidator);
        };

        new ReactiveWebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ZylosSecurityCommonAutoConfiguration.class, ZylosSecurityReactiveAutoConfiguration.class))
                .withPropertyValues(minimalProperties())
                .withBean(ZylosJwtValidatorCustomizer.class, () -> mockCustomizer)
                .run(context -> {
                    OAuth2TokenValidator<?> validator =
                            context.getBean("zylosReactiveJwtValidator", OAuth2TokenValidator.class);

                    @SuppressWarnings("unchecked")
                    Collection<OAuth2TokenValidator<Jwt>> delegates = (Collection<OAuth2TokenValidator<Jwt>>)
                            ReflectionTestUtils.getField(validator, "tokenValidators");

                    assertThat(delegates).hasSize(4);
                });
    }

    @Test
    void userProvidedJwtDecoderTakesPrecedence() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ZylosSecurityCommonAutoConfiguration.class, ZylosSecurityServletAutoConfiguration.class))
                .withPropertyValues(minimalProperties())
                .withBean("jwtDecoder", JwtDecoder.class, () -> _ -> null)
                .run(context -> {
                    JwtDecoder decoder = context.getBean(JwtDecoder.class);
                    assertThat(decoder).isNotInstanceOf(UnknownKidRefreshingJwtDecoder.class);
                });
    }

    @Test
    void audienceValidatorReceivesConfiguredAudience() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(ZylosSecurityCommonAutoConfiguration.class))
                .withUserConfiguration(StandaloneValidatorConfig.class)
                .withPropertyValues(minimalProperties())
                .run(context -> {
                    AudienceValidator av = context.getBean(AudienceValidator.class);
                    assertThat(av.expectedAudience()).isEqualTo("zylos-internal-hello");
                });
    }

    /**
     * Helper config exposing an AudienceValidator directly for assertion.
     */
    static class StandaloneValidatorConfig {

        @Bean
        AudienceValidator audienceValidator(ZylosSecurityProperties properties) {
            return new AudienceValidator(properties.expectedAudience());
        }
    }
}
