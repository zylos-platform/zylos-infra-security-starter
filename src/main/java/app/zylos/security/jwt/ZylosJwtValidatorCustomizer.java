package app.zylos.security.jwt;

import java.util.List;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Extension point for customizing the JWT validator chain built by
 * {@link ZylosJwtValidatorFactory}.
 *
 * <p>Beans of this type are discovered at startup and invoked in
 * {@link org.springframework.core.annotation.Order} precedence (lowest
 * value first) on a mutable list pre-populated with the Zylos built-in
 * validators in this order:
 * <ol>
 *   <li>{@link org.springframework.security.oauth2.jwt.JwtTimestampValidator}
 *       — {@code exp} / {@code nbf} with configured clock skew</li>
 *   <li>{@link org.springframework.security.oauth2.jwt.JwtIssuerValidator}
 *       — exact {@code iss} match</li>
 *   <li>{@link AudienceValidator}
 *       — {@code aud == self}, no multi-audience tolerance</li>
 * </ol>
 *
 * <p>Customizers may add, remove, replace, or reorder entries in the
 * provided list. The list is wrapped in a
 * {@link org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator}
 * after all customizers have run.
 *
 * <h2>Typical Usage</h2>
 * <pre>{@code
 * @Bean
 * ZylosJwtValidatorCustomizer myCustomizer() {
 *     return validators -> validators.add(new MyCustomJwtClaimValidator());
 * }
 * }</pre>
 *
 * <p>Removing built-ins is supported but rare; it's reserved for test
 * configurations and advanced overrides. Production services should
 * never strip issuer or audience validation.
 */
@FunctionalInterface
public interface ZylosJwtValidatorCustomizer {

    void customize(List<OAuth2TokenValidator<Jwt>> validators);
}
