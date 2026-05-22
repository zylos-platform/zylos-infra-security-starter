/**
 * Actor-chain authorization: extracts the {@code act} delegation chain from
 * a validated JWT, looks up the configured per-endpoint policy, and emits
 * an authorization decision.
 *
 * <p>Validation runs as a Spring Security
 * {@link org.springframework.security.authorization.AuthorizationManager} (servlet)
 * or {@link org.springframework.security.authorization.ReactiveAuthorizationManager}
 * (reactive) — denials produce HTTP 403, consistent with the authorization
 * (not authentication) nature of chain mismatches.
 */
@NullMarked
package app.zylos.security.actor;

import org.jspecify.annotations.NullMarked;
