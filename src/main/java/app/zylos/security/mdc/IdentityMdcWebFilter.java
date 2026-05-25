package app.zylos.security.mdc;

import java.util.UUID;

import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import app.zylos.security.properties.ZylosSecurityProperties;

import io.micrometer.context.ContextRegistry;
import io.micrometer.context.ThreadLocalAccessor;
import reactor.core.publisher.Mono;

/**
 * Reactive-stack equivalent of {@link IdentityMdcFilter}.
 *
 * <p>Writes the correlation ID and authenticated subject into the Reactor
 * Context for the duration of the request. Reactor's automatic context
 * propagation hook (enabled in consuming services via
 * {@code spring.reactor.context-propagation=auto} or
 * {@code Hooks.enableAutomaticContextPropagation()}) bridges these values
 * into MDC for logging.
 *
 * <p>{@link ThreadLocalAccessor} instances for the two MDC keys are
 * registered at construction time via {@link ContextRegistry}. Repeated
 * registration is safe (the registry overwrites existing accessors keyed
 * by their internal identifier).
 *
 * <p>Ordering is critical: this filter runs at
 * {@link Ordered#LOWEST_PRECEDENCE} so it executes after {@code
 * AuthenticationWebFilter}. By the time the inner chain filter is
 * subscribed, the SecurityContext is available via
 * {@link ReactiveSecurityContextHolder}.
 *
 * <p>Consumers that don't enable automatic context propagation still get
 * the values via Reactor Context — they're available to anyone calling
 * {@code Mono.deferContextual(ctx -> ctx.get("zylos.correlation_id"))} —
 * but log statements won't auto-include them.
 */
public record IdentityMdcWebFilter(ZylosSecurityProperties.MdcProperties props) implements WebFilter, Ordered {

    public IdentityMdcWebFilter {
        registerThreadLocalAccessors();
    }

    private void registerThreadLocalAccessors() {
        ContextRegistry.getInstance()
                .registerThreadLocalAccessor(
                        MdcKeys.CORRELATION_ID,
                        () -> MDC.get(MdcKeys.CORRELATION_ID),
                        value -> MDC.put(MdcKeys.CORRELATION_ID, value),
                        () -> MDC.remove(MdcKeys.CORRELATION_ID));

        ContextRegistry.getInstance()
                .registerThreadLocalAccessor(
                        MdcKeys.SUBJECT,
                        () -> MDC.get(MdcKeys.SUBJECT),
                        value -> MDC.put(MdcKeys.SUBJECT, value),
                        () -> MDC.remove(MdcKeys.SUBJECT));
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String correlationId = resolveCorrelationId(exchange);
        exchange.getResponse().getHeaders().set(props.correlationIdHeader(), correlationId);

        return ReactiveSecurityContextHolder.getContext()
                .mapNotNull(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .map(Authentication::getName)
                .filter(name -> !"anonymousUser".equals(name))
                .defaultIfEmpty("")
                .flatMap(subject -> {
                    Mono<Void> filterMono = chain.filter(exchange);

                    if (subject.isEmpty()) {
                        return filterMono.contextWrite(ctx -> ctx.put(MdcKeys.CORRELATION_ID, correlationId));
                    } else {
                        return filterMono.contextWrite(ctx ->
                                ctx.put(MdcKeys.CORRELATION_ID, correlationId).put(MdcKeys.SUBJECT, subject));
                    }
                });
    }

    private String resolveCorrelationId(ServerWebExchange exchange) {
        String fromHeader = exchange.getRequest().getHeaders().getFirst(props.correlationIdHeader());

        if (fromHeader != null && !fromHeader.isBlank()) {
            return fromHeader;
        }

        return UUID.randomUUID().toString();
    }
}
