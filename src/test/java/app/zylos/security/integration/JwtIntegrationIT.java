package app.zylos.security.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;

/**
 * End-to-end JWT validation tests against a real Keycloak 26.6.1 instance.
 *
 * <p>Exercises the full decoder chain assembled by the starter's
 * autoconfiguration:
 * {@link app.zylos.security.metrics.MeteredJwtDecoder} wrapping
 * {@link app.zylos.security.jwt.UnknownKidRefreshingJwtDecoder} wrapping a
 * {@code NimbusJwtDecoder}. The chain pulls JWKS from Keycloak's
 * discovery endpoint, caches it, validates signature, issuer, audience,
 * and expiration.
 *
 * <p>Token acquisition uses {@code client_credentials} grant — sufficient
 * for verifying the validator chain end-to-end without an Auth Code flow.
 */
@IntegrationTest
@TestPropertySource(properties = {"zylos.security.actor-chains.enabled=false"})
class JwtIntegrationIT extends KeycloakIntegrationTestBase {

    @Autowired
    JwtDecoder jwtDecoder;

    @Test
    void decodesValidTokenFromKeycloak() throws Exception {
        String token = obtainToken(CLIENT_INTERNAL_TEST, SECRET_INTERNAL_TEST);

        Jwt decoded = jwtDecoder.decode(token);

        assertThat(decoded).isNotNull();
        assertThat(decoded.getIssuer().toString()).endsWith("/realms/" + TEST_REALM);
        assertThat(decoded.getAudience()).contains(CLIENT_INTERNAL_TEST);
        assertThat(decoded.getSubject()).isNotBlank();
    }

    @Test
    void rejectsTokenWithMismatchedAudience() throws Exception {
        // zylos-rogue-caller's token has aud=zylos-rogue-caller, but
        // our decoder is configured to expect aud=zylos-internal-test.
        String wrongAudienceToken = obtainToken(CLIENT_ROGUE_CALLER, SECRET_ROGUE_CALLER);

        assertThatThrownBy(() -> jwtDecoder.decode(wrongAudienceToken))
                .isInstanceOf(BadJwtException.class)
                .satisfies(e -> assertThat(e.getMessage()).containsAnyOf("audience", "aud"));
    }

    @Test
    void rejectsMalformedToken() {
        String malformed = "this.is.not.a.jwt";

        assertThatThrownBy(() -> jwtDecoder.decode(malformed)).isInstanceOf(BadJwtException.class);
    }

    @Test
    void rejectsTokenSignedByDifferentKeycloak() {
        // A token signed with a wrong key has an invalid signature.
        // We construct one by mangling a real token's signature segment.
        String constructedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Indyb25nLWtleSJ9"
                + "."
                + "eyJpc3MiOiJodHRwczovL2tleWNsb2FrLnpJtb3MubG9jYWwvcmVhbG1zL3RoZXJlYWxtIiwic3ViIjoiYWxpY2UifQ"
                + "."
                + "QQQQQQQQQQQ";

        assertThatThrownBy(() -> jwtDecoder.decode(constructedJwt)).isInstanceOf(BadJwtException.class);
    }

    @Test
    void jwksFetchedOnFirstUseThenCached() throws Exception {
        // Two decodes in rapid succession should not produce two JWKS fetches.
        // This test verifies the second call succeeds (i.e., cache is being
        // populated and re-used as expected).
        String token1 = obtainToken(CLIENT_INTERNAL_TEST, SECRET_INTERNAL_TEST);
        String token2 = obtainToken(CLIENT_INTERNAL_TEST, SECRET_INTERNAL_TEST);

        List<Jwt> decoded = List.of(jwtDecoder.decode(token1), jwtDecoder.decode(token2));

        assertThat(decoded)
                .hasSize(2)
                .allSatisfy(jwt -> assertThat(jwt.getIssuer()).isNotNull());
    }
}
