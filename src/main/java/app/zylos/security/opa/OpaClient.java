package app.zylos.security.opa;

import org.jspecify.annotations.Nullable;

/**
 * Facade for evaluating policy decisions against an OPA server.
 *
 * <p>OPA's REST API surface used by this client is a single endpoint shape:
 * <pre>
 *   POST /v1/data/{policy/path}
 *   Content-Type: application/json
 *   Body: {"input": {...}}
 *
 *   Response 200:
 *   {"result": {...}}
 * </pre>
 *
 * <p>Two flavors of method:
 * <ul>
 *   <li>{@link #evaluate(String, Object, Class)} — typed decision result;
 *       caller specifies the expected response shape</li>
 *   <li>{@link #check(String, Object)} — boolean-only shortcut for the
 *       common case of {@code allow: true|false}</li>
 * </ul>
 *
 * <p>Implementations of this interface include both the HTTP client (servlet
 * {@link RestClientOpaClient} or reactive {@link WebClientOpaClient}) and
 * cross-cutting decorators such as {@link CachingOpaClient}.
 *
 * <p>Implementations MUST be thread-safe; the bean is shared across all
 * service threads.
 */
public interface OpaClient {

    /**
     * Evaluate a policy at the given path with the given input.
     *
     * @param policyPath OPA policy path including any package segments,
     *                   e.g. {@code "zylos/cart/allow"}. Leading slash optional; the
     *                   client prepends {@code /v1/data/} as required by OPA.
     * @param input      the value bound to OPA's {@code input} variable; must
     *                   be serializable by Jackson to a JSON object
     * @param resultType expected shape of OPA's {@code result} field
     * @param <T>        the response shape type parameter
     * @return the parsed decision, or {@code null} when OPA returns 200
     * with no {@code result} (typically interpreted as policy
     * undefined-rule denial)
     * @throws OpaDecisionException on HTTP errors, deserialization errors,
     *                              or timeouts; the message identifies the failure category
     */
    <T> @Nullable T evaluate(String policyPath, Object input, Class<T> resultType);

    /**
     * Convenience for policies returning {@code {"allow": true|false}} (or
     * a similar single-boolean shape). Defaults to {@code false} on any
     * failure mode (no response, missing field, exception) so authorization
     * failures fail closed.
     *
     * @param policyPath OPA policy path
     * @param input      the value bound to OPA's {@code input} variable
     * @return {@code true} when OPA explicitly returns {@code allow=true};
     * {@code false} otherwise (including on exceptions)
     */
    default boolean check(String policyPath, Object input) {
        try {
            OpaDecisionResponse response = evaluate(policyPath, input, OpaDecisionResponse.class);
            return response != null && Boolean.TRUE.equals(response.allow());
        } catch (OpaDecisionException _) {
            return false;
        }
    }
}
