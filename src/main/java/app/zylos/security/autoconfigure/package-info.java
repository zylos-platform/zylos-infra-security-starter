/**
 * Spring Boot auto-configuration classes for the Zylos security starter.
 *
 * <p>Three auto-configurations participate, in order:
 * <ol>
 *   <li>{@link app.zylos.security.autoconfigure.ZylosSecurityCommonAutoConfiguration}
 *       — properties and JWKS cache, stack-agnostic.</li>
 *   <li>{@link app.zylos.security.autoconfigure.ZylosSecurityServletAutoConfiguration}
 *       — servlet-stack {@code JwtDecoder} and validator chain.</li>
 *   <li>{@link app.zylos.security.autoconfigure.ZylosSecurityReactiveAutoConfiguration}
 *       — reactive-stack {@code ReactiveJwtDecoder} and validator chain.</li>
 * </ol>
 */
@NullMarked
package app.zylos.security.autoconfigure;

import org.jspecify.annotations.NullMarked;
