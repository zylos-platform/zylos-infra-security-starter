package app.zylos.security.opa;

import java.io.Serial;

import org.jspecify.annotations.Nullable;

/**
 * Thrown for any OPA-related failure during decision evaluation.
 */
public class OpaDecisionException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final Integer statusCode;

    public OpaDecisionException(String message) {
        super(message);
        this.statusCode = null;
    }

    public OpaDecisionException(String message, Throwable cause) {
        super(message, cause);
        this.statusCode = null;
    }

    public OpaDecisionException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public @Nullable Integer statusCode() {
        return statusCode;
    }
}
