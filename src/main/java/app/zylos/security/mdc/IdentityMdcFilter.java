package app.zylos.security.mdc;

import java.io.IOException;
import java.util.UUID;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import app.zylos.security.properties.ZylosSecurityProperties;

/**
 * Servlet-stack filter that enriches the MDC with the request's correlation
 * identifier and authenticated subject for the duration of the request.
 *
 * <p>The filter runs at {@link Ordered#LOWEST_PRECEDENCE} so it executes
 * after Spring Security's filter chain has populated the
 * {@link SecurityContextHolder} with the authenticated principal. The subject is
 * read from {@link Authentication#getName()} when present.
 *
 * <p>The correlation ID is taken from the configured request header (default
 * {@code X-Correlation-Id}); if absent, a fresh UUID is generated. The
 * correlation ID is always echoed in the response header so downstream
 * clients and logs share the same identifier.
 *
 * <p>MDC entries are removed in a {@code finally} block on the same thread
 * that invoked the filter; static initialization of MDC is unaffected for
 * keys this filter does not touch (notably {@code traceId}/{@code spanId}
 * from Micrometer Tracing).
 *
 * <p>The filter is idempotent — invoking it twice within the same request
 * (via {@link OncePerRequestFilter}'s built-in guard) is safe and re-uses
 * the existing correlation ID from the request attribute.
 */
public final class IdentityMdcFilter extends OncePerRequestFilter implements Ordered {

    private static final String ATTR_CORRELATION_ID = IdentityMdcFilter.class.getName() + ".correlationId";

    private final ZylosSecurityProperties.MdcProperties props;

    public IdentityMdcFilter(ZylosSecurityProperties.MdcProperties props) {
        this.props = props;
    }

    private static @Nullable String currentSubject() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getName())) {
            return null;
        }
        return auth.getName();
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String correlationId = resolveCorrelationId(request);
        response.setHeader(props.correlationIdHeader(), correlationId);

        String subject = currentSubject();

        try {
            MDC.put(MdcKeys.CORRELATION_ID, correlationId);

            if (subject != null) {
                MDC.put(MdcKeys.SUBJECT, subject);
            }

            chain.doFilter(request, response);

        } finally {
            MDC.remove(MdcKeys.CORRELATION_ID);
            MDC.remove(MdcKeys.SUBJECT);
        }
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        Object cached = request.getAttribute(ATTR_CORRELATION_ID);

        if (cached instanceof String existing && !existing.isBlank()) {
            return existing;
        }

        String fromHeader = request.getHeader(props.correlationIdHeader());
        String correlationId = (fromHeader != null && !fromHeader.isBlank())
                ? fromHeader
                : UUID.randomUUID().toString();
        request.setAttribute(ATTR_CORRELATION_ID, correlationId);
        return correlationId;
    }
}
