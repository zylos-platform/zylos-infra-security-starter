package app.zylos.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

class AudienceValidatorTest {

    private static final String EXPECTED = "zylos-internal-hello";
    private final AudienceValidator validator = new AudienceValidator(EXPECTED);

    private static Jwt jwtWithAudience(List<String> audiences) {
        Jwt.Builder builder = Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .header("kid", "test-key")
                .issuer("https://keycloak.zylos.local/realms/zylos")
                .subject("alice")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(900))
                .claim("custom", Map.of("k", "v"));

        if (audiences != null) {
            builder.audience(audiences);
        }

        return builder.build();
    }

    @Test
    void acceptsTokenWithExactAudience() {
        Jwt jwt = jwtWithAudience(List.of(EXPECTED));

        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void acceptsTokenWhenExpectedAudienceIsOneOfMany() {
        // While our token-exchange design produces single-audience tokens, the
        // validator must still accept multi-aud tokens that include the expected.
        Jwt jwt = jwtWithAudience(List.of("zylos-gateway", EXPECTED, "other"));

        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"zylos-gateway", "zylos-internal-other", "zylos-other-service"})
    void rejectsTokenWithWrongAudience(String wrongAudience) {
        Jwt jwt = jwtWithAudience(List.of(wrongAudience));

        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .anyMatch(e -> e.getErrorCode().equals("invalid_audience"))
                .anyMatch(e -> e.getDescription().contains(EXPECTED));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsTokenWithMissingAudience(List<String> audience) {
        Jwt jwt = jwtWithAudience(audience);

        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void exposesConfiguredAudience() {
        assertThat(validator.expectedAudience()).isEqualTo(EXPECTED);
    }
}
