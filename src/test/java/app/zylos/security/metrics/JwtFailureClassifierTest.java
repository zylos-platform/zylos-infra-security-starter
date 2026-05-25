package app.zylos.security.metrics;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

class JwtFailureClassifierTest {

    private static Stream<Arguments> classificationCases() {
        List<OAuth2Error> dummyErrors = List.of(new OAuth2Error("invalid_token"));

        return Stream.of(
                Arguments.of(
                        new BadJwtException("Signed JWT rejected: Invalid signature"),
                        JwtFailureClassifier.FailureReason.INVALID_SIGNATURE),
                Arguments.of(
                        new BadJwtException("Couldn't retrieve remote JWK set"),
                        JwtFailureClassifier.FailureReason.INVALID_SIGNATURE),
                Arguments.of(
                        new BadJwtException("No matching key found"),
                        JwtFailureClassifier.FailureReason.INVALID_SIGNATURE),
                Arguments.of(
                        new BadJwtException("Completely unparseable string token payload"),
                        JwtFailureClassifier.FailureReason.MALFORMED),
                Arguments.of(
                        new JwtValidationException("Jwt expired at 2024-01-01", dummyErrors),
                        JwtFailureClassifier.FailureReason.EXPIRED),
                Arguments.of(
                        new JwtValidationException("Jwt is not yet valid", dummyErrors),
                        JwtFailureClassifier.FailureReason.NOT_YET_VALID),
                Arguments.of(
                        new JwtValidationException("The required audience 'zylos-cart' is missing", dummyErrors),
                        JwtFailureClassifier.FailureReason.INVALID_AUDIENCE),
                Arguments.of(
                        new JwtValidationException("invalid_audience: aud claim missing", dummyErrors),
                        JwtFailureClassifier.FailureReason.INVALID_AUDIENCE),
                Arguments.of(
                        new JwtValidationException("The iss claim is not equal to expected", dummyErrors),
                        JwtFailureClassifier.FailureReason.INVALID_ISSUER),
                Arguments.of(
                        new JwtValidationException("invalid_issuer", dummyErrors),
                        JwtFailureClassifier.FailureReason.INVALID_ISSUER),
                Arguments.of(
                        new JwtValidationException("Some unknown failure mode", dummyErrors),
                        JwtFailureClassifier.FailureReason.OTHER));
    }

    @ParameterizedTest
    @MethodSource("classificationCases")
    void classifiesJwtExceptionByHierarchyAndMessage(
            JwtException exception, JwtFailureClassifier.FailureReason expectedCategory) {
        assertThat(JwtFailureClassifier.classify(exception)).isEqualTo(expectedCategory);
    }

    @Test
    void classifiesNonBadJwtAsMalformed() {
        JwtException generic = new JwtException("Token cannot be parsed");
        assertThat(JwtFailureClassifier.classify(generic)).isEqualTo(JwtFailureClassifier.FailureReason.OTHER);
    }

    @Test
    void classifiesNullMessageAsOther() {
        BadJwtException exception = new BadJwtException("");
        // Empty string message; falls through to "other"
        assertThat(JwtFailureClassifier.classify(exception)).isEqualTo(JwtFailureClassifier.FailureReason.OTHER);
    }
}
