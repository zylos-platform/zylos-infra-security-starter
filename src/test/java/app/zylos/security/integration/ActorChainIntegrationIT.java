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
 * End-to-end actor-chain authorization tests against a real Keycloak with
 * V2 standard token exchange (RFC 8693).
 *
 * <p>Acquires real tokens from Keycloak — including tokens produced via
 * token exchange with populated {@code act} claims — and exercises the
 * {@link ActorChainAuthorizationManager} decision flow. This is the highest-confidence
 * test of the actor-chain implementation because every layer
 * (Keycloak token issuance, exchange semantics, our extractor, our matcher)
 * is real.
 *
 * <p>The test uses a programmatically-constructed {@link ActorChainsRegistry}
 * rather than the YAML-loaded one so each test can declare its own
 * permitted-chains policy without authoring multiple YAML files.
 */
@IntegrationTest
@TestPropertySource(
        properties = {"zylos.security.actor-chains.enabled=false" // We supply our own registry below
        })
class ActorChainIntegrationIT extends KeycloakIntegrationTestBase {

    @Autowired
    JwtDecoder jwtDecoder;

    // --- helpers -------------------------------------------------------

    private static ActorChainEvaluator evaluatorWith(EndpointChainRule rule) {
        ActorChainsRegistry registry =
                new ActorChainsRegistry(new ActorChainsConfig(ChainDefaults.strict(), List.of(rule)));
        return new ActorChainEvaluator(registry, new SimpleMeterRegistry());
    }

    private static EndpointChainRule rule(String pattern, List<List<String>> permitted, boolean publicAccess) {
        return new EndpointChainRule(pattern, permitted, publicAccess);
    }

    private static Authentication jwtAuth(Jwt jwt) {
        return new JwtAuthenticationToken(jwt, List.of());
    }

    private static RequestAuthorizationContext contextFor(String path) {
        HttpServletRequest request = new MockHttpServletRequest("GET", path);
        return new RequestAuthorizationContext(request);
    }

    @Test
    void mismatchedChainDenied() throws Exception {
        // Permitted: [gateway]; actual chain: [internal-caller]
        ActorChainEvaluator evaluator = evaluatorWith(rule("/api/v1/test", List.of(List.of(CLIENT_GATEWAY)), false));
        ActorChainAuthorizationManager manager = new ActorChainAuthorizationManager(evaluator);

        String callerToken = obtainToken(CLIENT_INTERNAL_CALLER, SECRET_INTERNAL_CALLER);
        String exchanged =
                exchangeToken(CLIENT_INTERNAL_CALLER, SECRET_INTERNAL_CALLER, callerToken, CLIENT_INTERNAL_TEST);
        Jwt exchangedJwt = jwtDecoder.decode(exchanged);

        AuthorizationDecision decision = manager.authorize(() -> jwtAuth(exchangedJwt), contextFor("/api/v1/test"));

        assertThat(decision).isNotNull();
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void publicEndpointPermitsWithoutChain() {
        // No token, but path is marked public.
        ActorChainEvaluator evaluator = evaluatorWith(rule("/api/v1/public", List.of(), true));
        ActorChainAuthorizationManager manager = new ActorChainAuthorizationManager(evaluator);

        AuthorizationDecision decision = manager.authorize(() -> null, contextFor("/api/v1/public"));

        assertThat(decision).isNotNull();
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void noMatchingPathDeniedByStrictDefault() throws Exception {
        ActorChainEvaluator evaluator = evaluatorWith(rule("/api/v1/known", List.of(List.of(CLIENT_GATEWAY)), false));
        ActorChainAuthorizationManager manager = new ActorChainAuthorizationManager(evaluator);

        String token = obtainToken(CLIENT_GATEWAY, SECRET_GATEWAY);
        String exchanged = exchangeToken(CLIENT_GATEWAY, SECRET_GATEWAY, token, CLIENT_INTERNAL_TEST);
        Jwt exchangedJwt = jwtDecoder.decode(exchanged);

        AuthorizationDecision decision = manager.authorize(() -> jwtAuth(exchangedJwt), contextFor("/api/v1/unknown"));

        assertThat(decision).isNotNull();
        assertThat(decision.isGranted()).isFalse();
    }
}
