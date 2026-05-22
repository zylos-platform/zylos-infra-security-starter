package app.zylos.security.jwt;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;

import app.zylos.security.properties.ZylosSecurityProperties;

/**
 * Builds the Zylos JWT validator chain composed of built-in validators
 * (timestamp, issuer, audience) plus any
 * {@link ZylosJwtValidatorCustomizer} beans present in the application
 * context.
 *
 * <p>The same factory serves both the servlet
 * ({@link app.zylos.security.autoconfigure.ZylosSecurityServletAutoConfiguration})
 * and reactive
 * ({@link app.zylos.security.autoconfigure.ZylosSecurityReactiveAutoConfiguration})
 * auto-configurations because {@link OAuth2TokenValidator}{@code <}{@link Jwt}{@code >}
 * is stack-agnostic.
 *
 * <p>Each invocation produces a fresh validator chain; the factory holds
 * no mutable state.
 */
public final class ZylosJwtValidatorFactory {

    private ZylosJwtValidatorFactory() {
        // Utility class
    }

    /**
     * Build the validator chain.
     *
     * @param properties  bound configuration; supplies clock skew, issuer
     *                    URI, and expected audience
     * @param customizers customizer beans discovered in the application
     *                    context; invoked in {@code @Order} precedence after built-in
     *                    validators are added
     * @return a {@link org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator}
     * wrapping the final composed list
     */
    public static OAuth2TokenValidator<Jwt> create(
            ZylosSecurityProperties properties, ObjectProvider<ZylosJwtValidatorCustomizer> customizers) {

        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();

        validators.add(new JwtTimestampValidator(properties.clockSkew()));
        validators.add(new JwtIssuerValidator(properties.issuerUri()));
        validators.add(new AudienceValidator(properties.expectedAudience()));

        customizers.orderedStream().forEach(customizer -> customizer.customize(validators));

        return new DelegatingOAuth2TokenValidator<>(validators);
    }
}
