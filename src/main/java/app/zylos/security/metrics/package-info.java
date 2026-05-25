/**
 * Identity-related Micrometer metrics for Zylos services.
 *
 * <p>The starter publishes metrics from several layers; this package owns
 * the JWT-validation metrics specifically. Other identity metrics are
 * registered by the components that originate them:
 *
 * <ul>
 *   <li>JWKS forced refresh: {@code
 *       app.zylos.security.jwt.UnknownKidRefreshingJwtDecoder}</li>
 *   <li>Actor chain decisions: {@code
 *       app.zylos.security.actor.ActorChainEvaluator}</li>
 *   <li>OPA decisions and cache stats: {@code
 *       app.zylos.security.opa.WebClientOpaClient},
 *       {@code RestClientOpaClient}, {@code ReactiveCachingOpaClient}</li>
 * </ul>
 *
 * <p>JWKS cache statistics (hits, misses, evictions, load duration) are
 * registered by the common autoconfiguration via Micrometer's standard
 * Caffeine binder, with cache name {@code zylos_jwks_cache}.
 */
@NullMarked
package app.zylos.security.metrics;

import org.jspecify.annotations.NullMarked;
