/**
 * Request-scoped MDC enrichment for Zylos services.
 *
 * <p>Two filter implementations parallel each other:
 * {@link app.zylos.security.mdc.IdentityMdcFilter} for the servlet stack and
 * {@link app.zylos.security.mdc.IdentityMdcWebFilter} for the reactive stack. Both
 * populate the MDC with a per-request correlation ID (extracted from the
 * configured request header or generated if absent) and the authenticated
 * subject when available.
 *
 * <p>Trace ID and span ID are populated by Micrometer Tracing (provided by
 * Spring Boot's actuator dependency); the starter does not duplicate that
 * work.
 *
 * <p>For the reactive stack, consumers must enable Reactor's automatic
 * context propagation:
 * <pre>{@code
 * # application.yaml
 * spring:
 *   reactor:
 *     context-propagation: auto
 * }</pre>
 * Without this, the values reach the Reactor Context but are not bridged
 * into MDC for log statements.
 */
@NullMarked
package app.zylos.security.mdc;

import org.jspecify.annotations.NullMarked;
