package app.zylos.security.opa;

/**
 * Envelope wrapping caller-supplied input as OPA expects on the wire.
 *
 * <p>OPA's data API requires the body to be {@code {"input": <value>}};
 * this record produces that JSON shape via Jackson without ceremony.
 *
 * @param input the value bound to OPA's {@code input} variable
 */
public record OpaDecisionRequest(Object input) {

    public static OpaDecisionRequest of(Object input) {
        return new OpaDecisionRequest(input);
    }
}
