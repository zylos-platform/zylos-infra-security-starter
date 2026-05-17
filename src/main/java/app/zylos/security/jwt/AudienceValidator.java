package app.zylos.security.jwt;

import java.util.List;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Validates that the JWT's {@code aud} claim contains the configured expected
 * audience. Every service rejects tokens not bound to its audience, even if the
 * signature and issuer are correct.
 *
 * <p>The expected audience must appear in the {@code aud} array.
 * Tokens are bound to exactly one audience via RFC 8693 token exchange, so
 * accepting any additional audience would defeat the downscoping invariant.
 *
 * <p>Error code {@code invalid_audience} aligns with Spring Security's
 * convention for surfacing claim-validation failures to actuator and audit
 * pipelines.
 */
public record AudienceValidator(String expectedAudience) implements OAuth2TokenValidator<Jwt> {

    private static final String ERROR_CODE = "invalid_audience";
    private static final String ERROR_DESCRIPTION_TEMPLATE =
            "The required audience '%s' is missing from the token's aud claim.";

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> audiences = jwt.getAudience();

        if (audiences != null && audiences.contains(expectedAudience)) {
            return OAuth2TokenValidatorResult.success();
        }

        OAuth2Error error = new OAuth2Error(ERROR_CODE, ERROR_DESCRIPTION_TEMPLATE.formatted(expectedAudience), null);

        return OAuth2TokenValidatorResult.failure(error);
    }
}
