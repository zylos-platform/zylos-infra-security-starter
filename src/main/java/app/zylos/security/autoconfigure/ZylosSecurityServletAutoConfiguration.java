package app.zylos.security.autoconfigure;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.cache.Cache;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;

import app.zylos.security.jwt.AudienceValidator;
import app.zylos.security.jwt.UnknownKidRefreshingJwtDecoder;
import app.zylos.security.jwt.ZylosJwtValidatorCustomizer;
import app.zylos.security.jwt.ZylosJwtValidatorFactory;
import app.zylos.security.properties.ZylosSecurityProperties;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

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
    @ConditionalOnMissingBean
    public MeterRegistry zylosSecurityFallbackMeterRegistry() {
        // Services should already provide a Micrometer registry; this is a fallback
        // so the starter doesn't break in tests / minimal setups.
        return new SimpleMeterRegistry();
    }

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
        NimbusJwtDecoder nimbus = NimbusJwtDecoder.withIssuerLocation(properties.issuerUri())
                .cache(jwksCache)
                .build();

        nimbus.setJwtValidator(zylosJwtValidator);

        return new UnknownKidRefreshingJwtDecoder(nimbus, jwksCache, properties.issuerUri(), meterRegistry);
    }
}
