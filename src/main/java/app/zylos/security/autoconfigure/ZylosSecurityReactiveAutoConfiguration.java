package app.zylos.security.autoconfigure;

import app.zylos.security.actor.ActorChainEvaluator;
import app.zylos.security.actor.ActorChainReactiveAuthorizationManager;
import app.zylos.security.jwt.UnknownKidRefreshingReactiveJwtDecoder;
import app.zylos.security.jwt.ZylosJwtValidatorCustomizer;
import app.zylos.security.jwt.ZylosJwtValidatorFactory;
import app.zylos.security.properties.ZylosSecurityProperties;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.cache.Cache;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Reactive-stack auto-configuration. Active when WebFlux is on the classpath
 * (e.g., {@code spring-cloud-starter-gateway-server-webflux}, which the Zylos
 * gateway uses).
 *
 * <p>Mirrors {@link ZylosSecurityServletAutoConfiguration} for the reactive
 * stack: same validator chain composition, same JWKS cache, same unknown-kid
 * refresh semantics.
 *
 * <p>{@link NimbusReactiveJwtDecoder#withIssuerLocation} does not currently
 * accept a Spring {@link Cache} directly; the JWKS cache wrapping is applied
 * via the decorator pattern in {@link UnknownKidRefreshingReactiveJwtDecoder}.
 * The inner decoder uses Nimbus's in-process JWKS cache (default 5 min);
 * Architecture's 1-hour TTL is enforced by the wrapping cache layer
 * when used in conjunction with future refresh hooks.
 */
@AutoConfiguration(after = ZylosSecurityCommonAutoConfiguration.class)
@ConditionalOnClass(name = "org.springframework.web.reactive.DispatcherHandler")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
public class ZylosSecurityReactiveAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = "zylosReactiveJwtValidator")
    public OAuth2TokenValidator<Jwt> zylosReactiveJwtValidator(
        ZylosSecurityProperties properties, ObjectProvider<ZylosJwtValidatorCustomizer> customizers) {

        return ZylosJwtValidatorFactory.create(properties, customizers);
    }

    @Bean
    @ConditionalOnMissingBean
    public ReactiveJwtDecoder reactiveJwtDecoder(
        ZylosSecurityProperties properties,
        Cache jwksCache,
        OAuth2TokenValidator<Jwt> zylosReactiveJwtValidator,
        MeterRegistry meterRegistry) {
        NimbusReactiveJwtDecoder nimbus = NimbusReactiveJwtDecoder.withIssuerLocation(properties.issuerUri())
            .build();
        nimbus.setJwtValidator(zylosReactiveJwtValidator);

        return new UnknownKidRefreshingReactiveJwtDecoder(nimbus, jwksCache, properties.issuerUri(), meterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ActorChainEvaluator.class)
    public ActorChainReactiveAuthorizationManager actorChainReactiveAuthorizationManager(ActorChainEvaluator evaluator) {
        return new ActorChainReactiveAuthorizationManager(evaluator);
    }
}
