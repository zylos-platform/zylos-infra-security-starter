package app.zylos.security.autoconfigure;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.cache.Cache;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;

import app.zylos.security.actor.ActorChainAuthorizationManager;
import app.zylos.security.actor.ActorChainEvaluator;
import app.zylos.security.jwt.AudienceValidator;
import app.zylos.security.jwt.UnknownKidRefreshingJwtDecoder;
import app.zylos.security.jwt.ZylosJwtValidatorCustomizer;
import app.zylos.security.jwt.ZylosJwtValidatorFactory;
import app.zylos.security.mdc.IdentityMdcFilter;
import app.zylos.security.metrics.MeteredJwtDecoder;
import app.zylos.security.properties.ZylosSecurityProperties;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * Servlet-stack autoconfiguration. Active when {@code spring-boot-starter-web}
 * is on the classpath.
 *
 * <p>Composes the standard Zylos JWT validator chain:
 * <ol>
 *   <li>{@link JwtTimestampValidator} with the configured clock skew (default 30s)</li>
 *   <li>{@link JwtIssuerValidator} enforcing exact {@code iss} match</li>
 *   <li>{@link AudienceValidator} enforcing {@code aud == self}</li>
 *   <li>Any additional {@link OAuth2TokenValidator}&lt;{@link Jwt}&gt; beans in
 *       the context</li>
 * </ol>
 *
 * <p>The {@link JwtDecoder} is built from {@link NimbusJwtDecoder#withIssuerLocation}
 * with the configured issuer URI; metadata discovery happens once at startup.
 * The JWKS cache injected via {@code .cache(Cache)} is shared via the bean
 * named {@link ZylosSecurityCommonAutoConfiguration#JWKS_CACHE_BEAN_NAME}.
 *
 * <p>The decoder is then wrapped by {@link UnknownKidRefreshingJwtDecoder}
 * so that key-rotation events resolve transparently.
 */
@AutoConfiguration(after = ZylosSecurityCommonAutoConfiguration.class)
@ConditionalOnClass(name = "org.springframework.web.servlet.DispatcherServlet")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class ZylosSecurityServletAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = "zylosJwtValidator")
    public OAuth2TokenValidator<Jwt> zylosJwtValidator(
            ZylosSecurityProperties properties, ObjectProvider<ZylosJwtValidatorCustomizer> customizers) {

        return ZylosJwtValidatorFactory.create(properties, customizers);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoder(
            ZylosSecurityProperties properties,
            Cache jwksCache,
            OAuth2TokenValidator<Jwt> zylosJwtValidator,
            MeterRegistry meterRegistry) {

        NimbusJwtDecoder nimbus;
        String networkUri;

        if (properties.jwkSetUri() != null && !properties.jwkSetUri().isBlank()) {
            nimbus = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri())
                    .cache(jwksCache)
                    .build();
            networkUri = properties.jwkSetUri();
        } else {
            nimbus = NimbusJwtDecoder.withIssuerLocation(properties.issuerUri())
                    .cache(jwksCache)
                    .build();
            networkUri = properties.issuerUri();
        }

        nimbus.setJwtValidator(zylosJwtValidator);

        JwtDecoder withKidRefresh = new UnknownKidRefreshingJwtDecoder(nimbus, jwksCache, networkUri, meterRegistry);
        return new MeteredJwtDecoder(withKidRefresh, meterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean(IdentityMdcFilter.class)
    @ConditionalOnProperty(prefix = "zylos.security.mdc", name = "enabled", havingValue = "true", matchIfMissing = true)
    public IdentityMdcFilter identityMdcFilter(ZylosSecurityProperties properties) {
        return new IdentityMdcFilter(properties.mdc());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ActorChainEvaluator.class)
    public ActorChainAuthorizationManager actorChainAuthorizationManager(ActorChainEvaluator evaluator) {
        return new ActorChainAuthorizationManager(evaluator);
    }
}
