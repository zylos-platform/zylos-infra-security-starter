package app.zylos.security.metrics;

import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

public final class JwtFailureClassifier {

    private JwtFailureClassifier() {}

    public static FailureReason classify(JwtException exception) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) {
            return FailureReason.OTHER;
        }

        String lower = message.toLowerCase();

        if (exception instanceof JwtValidationException) {
            if (containsAny(lower, "expired", "exp claim")) return FailureReason.EXPIRED;
            if (containsAny(lower, "not yet valid", "nbf claim")) return FailureReason.NOT_YET_VALID;
            if (containsAny(lower, "invalid_audience", "audience")) return FailureReason.INVALID_AUDIENCE;
            if (containsAny(lower, "invalid_issuer", "iss claim", "issuer")) return FailureReason.INVALID_ISSUER;

            return FailureReason.OTHER;
        }

        if (exception instanceof BadJwtException) {
            if (containsAny(lower, "signature", "jwk", "matching key")) {
                return FailureReason.INVALID_SIGNATURE;
            }
            return FailureReason.MALFORMED;
        }

        return FailureReason.OTHER;
    }

    private static boolean containsAny(String haystack, String... needles) {
        for (String needle : needles) {
            if (haystack.contains(needle.toLowerCase())) return true;
        }
        return false;
    }

    public enum FailureReason {
        INVALID_SIGNATURE("invalid_signature"),
        EXPIRED("expired"),
        NOT_YET_VALID("not_yet_valid"),
        INVALID_AUDIENCE("invalid_audience"),
        INVALID_ISSUER("invalid_issuer"),
        MALFORMED("malformed"),
        OTHER("other");

        private final String tagValue;

        FailureReason(String tagValue) {
            this.tagValue = tagValue;
        }

        public String getTagValue() {
            return tagValue;
        }
    }
}
