package app.zylos.security.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.test.context.TestPropertySource;

import app.zylos.security.actor.*;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

/**
 * End-to-end actor-chain authorization tests against a real Keycloak (V2
 * standard token exchange), exercising the model (ADR 0003 refinement).
 *
 * <p>These tests run real tokens — acquired via {@code client_credentials} and
 * RFC 8693 token exchange — through the real {@link JwtDecoder} bean and the
 * real {@link ActorChainAuthorizationManager}. They cover every part of the
 * decision flow that does not require the {@code act} claim to be
 * populated:
 *
 * <ul>
 *   <li>public access (permit without a token);</li>
 *   <li>non-chain-sensitive endpoints (authenticated-only permit);</li>
 *   <li>standard defaults (unmatched path permits an authenticated caller);</li>
 *   <li>chain-sensitive wiring with the empty-chain guard (a real, act-less
 *       token is denied on a chainSensitive endpoint);</li>
 *   <li>strict no-match deny.</li>
 * </ul>
 *
 * <p><strong>Coverage boundary.</strong> The security starter's integration
 * tests run against <em>vanilla</em> Keycloak ({@code quay.io/keycloak/keycloak})
 * via the dasniko Testcontainers module, which does not populate the RFC 8693
 * {@code act} claim. The positive chain-match path (a populated {@code act}
 * matching a permitted chain) is therefore covered elsewhere:
 * <ul>
 *   <li>the mapper's production of a correctly-shaped {@code act} is verified
 *       by {@code ActClaimMapperIT} in {@code zylos-infra-keycloak-extensions};</li>
 *   <li>the extractor's parsing and the matcher's logic are verified by
 *       {@code ActChainExtractorTest}, {@code ActorChainEvaluatorTest}, and
 *       {@code ActorChainAuthorizationManagerTest} (synthesized {@code act});</li>
 *   <li>the full wiring (real {@code act} → real decode → authorization) is
 *       deferred to the service-level integration test,
 *       which runs against the cluster's custom Keycloak image.</li>
 * </ul>
 * See ADR 0006 for the rationale.
 *
 * <p>Each test constructs an {@link ActorChainsRegistry} programmatically so it
 * can declare its own policy without authoring multiple YAML files.
 */
@IntegrationTest
@TestPropertySource(properties = {"zylos.security.actor-chains.enabled=false"})
class ActorChainIntegrationIT extends KeycloakIntegrationTestBase {

    @Autowired
    JwtDecoder jwtDecoder;

    // --- helpers -------------------------------------------------------

    private static ActorChainAuthorizationManager manager(ChainDefaults defaults, EndpointChainRule... rules) {
        ActorChainsRegistry registry = new ActorChainsRegistry(new ActorChainsConfig(defaults, List.of(rules)));
        return new ActorChainAuthorizationManager(new ActorChainEvaluator(registry, new SimpleMeterRegistry()));
    }

    private static EndpointChainRule rule(
            String pattern, List<List<String>> permitted, boolean publicAccess, boolean chainSensitive) {
        return new EndpointChainRule(pattern, permitted, publicAccess, chainSensitive);
    }

    private static Authentication jwtAuth(Jwt jwt) {
        return new JwtAuthenticationToken(jwt, List.of());
    }

    private static RequestAuthorizationContext contextFor(String path) {
        HttpServletRequest request = new MockHttpServletRequest("GET", path);
        return new RequestAuthorizationContext(request);
    }

    @Test
    void publicEndpointPermitsWithoutToken() {
        ActorChainAuthorizationManager manager =
                manager(ChainDefaults.standard(), rule("/api/v1/public", List.of(), true, false));

        AuthorizationDecision decision = manager.authorize(() -> null, contextFor("/api/v1/public"));

        assertThat(decision).isNotNull();
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void nonSensitiveEndpointPermitsRealAuthenticatedToken() throws Exception {
        // A real, validly-signed token decoded by the real decoder. The endpoint
        // is chainSensitive=false, so a valid token is sufficient — the (absent)
        // act chain is never consulted.
        ActorChainAuthorizationManager manager =
                manager(ChainDefaults.standard(), rule("/api/v1/cart", List.of(), false, false));

        String token = obtainToken(CLIENT_INTERNAL_TEST, SECRET_INTERNAL_TEST);
        Jwt jwt = jwtDecoder.decode(token);

        AuthorizationDecision decision = manager.authorize(() -> jwtAuth(jwt), contextFor("/api/v1/cart"));

        assertThat(decision).isNotNull();
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void unmatchedPathUnderStandardDefaultsPermitsAuthenticatedToken() throws Exception {
        // standard: a path with no matching rule permits an authenticated
        // caller (rejectIfNoPathMatch=false).
        ActorChainAuthorizationManager manager =
                manager(ChainDefaults.standard(), rule("/api/v1/known", List.of(), false, false));

        String token = obtainToken(CLIENT_INTERNAL_TEST, SECRET_INTERNAL_TEST);
        Jwt jwt = jwtDecoder.decode(token);

        AuthorizationDecision decision = manager.authorize(() -> jwtAuth(jwt), contextFor("/api/v1/unlisted"));

        assertThat(decision).isNotNull();
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void unmatchedPathUnderStrictDefaultsDeniesRealToken() throws Exception {
        ActorChainAuthorizationManager manager =
                manager(ChainDefaults.strict(), rule("/api/v1/known", List.of(List.of(CLIENT_GATEWAY)), false, true));

        String token = obtainToken(CLIENT_GATEWAY, SECRET_GATEWAY);
        String exchanged = exchangeToken(CLIENT_GATEWAY, SECRET_GATEWAY, token, CLIENT_INTERNAL_TEST);
        Jwt jwt = jwtDecoder.decode(exchanged);

        AuthorizationDecision decision = manager.authorize(() -> jwtAuth(jwt), contextFor("/api/v1/unknown"));

        assertThat(decision).isNotNull();
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void chainSensitiveEndpointDeniesRealTokenWithoutActClaim() throws Exception {
        // A real exchanged token from vanilla Keycloak carries NO act claim.
        // On a chainSensitive endpoint with allowEmptyChain=false, this is
        // correctly denied with reason "empty_chain". This proves the
        // chainSensitive path executes end-to-end against a real token and that
        // the empty-chain guard fires.
        ActorChainAuthorizationManager manager = manager(
                ChainDefaults.standard(), rule("/api/v1/payments", List.of(List.of(CLIENT_GATEWAY)), false, true));

        String token = obtainToken(CLIENT_GATEWAY, SECRET_GATEWAY);
        String exchanged = exchangeToken(CLIENT_GATEWAY, SECRET_GATEWAY, token, CLIENT_INTERNAL_TEST);
        Jwt jwt = jwtDecoder.decode(exchanged);

        AuthorizationDecision decision = manager.authorize(() -> jwtAuth(jwt), contextFor("/api/v1/payments"));

        assertThat(decision).isNotNull();
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void chainSensitiveEndpointDeniesUnauthenticatedRequest() {
        ActorChainAuthorizationManager manager = manager(
                ChainDefaults.standard(), rule("/api/v1/payments", List.of(List.of(CLIENT_GATEWAY)), false, true));

        AuthorizationDecision decision = manager.authorize(() -> null, contextFor("/api/v1/payments"));

        assertThat(decision).isNotNull();
        assertThat(decision.isGranted()).isFalse();
    }
}
