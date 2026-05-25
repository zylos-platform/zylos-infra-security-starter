package app.zylos.security.mdc;

/**
 * MDC key constants used by the Zylos security starter.
 *
 * <p>These keys are populated by {@link IdentityMdcFilter} (servlet) /
 * {@link IdentityMdcWebFilter} (reactive). The trace ID and span ID keys
 * are populated by Micrometer Tracing (provided by Spring Boot's actuator
 * starter); the starter does not write them.
 *
 * <p>Consumers can reference these constants in logback patterns:
 * <pre>{@code
 * <pattern>%d{ISO8601} [%thread] %X{zylos.correlation_id:-} %X{zylos.subject:-} %X{traceId:-} - %msg%n</pattern>
 * }</pre>
 *
 * <p>Or programmatically via {@code MDC.get(MdcKeys.CORRELATION_ID)}.
 *
 * <p>The key names are stable across versions; changing them is a breaking
 * change for consumers' log configurations.
 */
public final class MdcKeys {

    /**
     * Per-request correlation identifier. Always populated.
     */
    public static final String CORRELATION_ID = "zylos.correlation_id";

    /**
     * Authenticated subject (typically the user's subclaim or service-account name).
     */
    public static final String SUBJECT = "zylos.subject";

    /**
     * Trace ID populated by Micrometer Tracing. Listed here for documentation.
     */
    public static final String TRACE_ID = "traceId";

    /**
     * Span ID populated by Micrometer Tracing. Listed here for documentation.
     */
    public static final String SPAN_ID = "spanId";

    private MdcKeys() {
        // Constants only.
    }
}
