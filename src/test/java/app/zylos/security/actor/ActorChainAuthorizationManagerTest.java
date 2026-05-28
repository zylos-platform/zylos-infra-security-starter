package app.zylos.security.actor;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class ActorChainAuthorizationManagerTest {

    private ActorChainAuthorizationManager manager;
    private MeterRegistry meterRegistry;

    private static Supplier<Authentication> authWithChain(List<String> chain) {
        Object actClaim = null;
        for (String actor : chain) {
            actClaim = actClaim == null ? Map.of("client_id", actor) : Map.of("client_id", actor, "act", actClaim);
        }
        Jwt.Builder builder = Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .subject("alice")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300));
        if (actClaim != null) {
            builder.claim("act", actClaim);
        }
        Authentication authentication = new JwtAuthenticationToken(builder.build(), List.of());
        return () -> authentication;
    }

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        ActorChainsConfig config = new ActorChainsConfig(
                ChainDefaults.strict(),
                List.of(
                        new EndpointChainRule("/api/v1/hello/public", List.of(), true, false),
                        // Chain-sensitive: the chain must match.
                        new EndpointChainRule(
                                "/api/v1/hello/me",
                                List.of(List.of("zylos-gateway"), List.of("zylos-mobile-bff", "zylos-gateway")),
                                false,
                                true),
                        new EndpointChainRule(
                                "/api/v1/hello/seller/**", List.of(List.of("zylos-gateway")), false, true),
                        // Non-sensitive: authenticated token suffices, no chain match.
                        new EndpointChainRule("/api/v1/hello/browse", List.of(), false, false)));
        ActorChainEvaluator evaluator = new ActorChainEvaluator(new ActorChainsRegistry(config), meterRegistry);
        manager = new ActorChainAuthorizationManager(evaluator);
    }

    @Test
    void publicEndpointIsPermittedRegardlessOfChain() {
        AuthorizationDecision decision = decide(authWithChain(List.of()), "/api/v1/hello/public");
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void noMatchingPathIsDeniedUnderStrictDefaults() {
        AuthorizationDecision decision = decide(authWithChain(List.of("zylos-gateway")), "/api/v1/unknown");
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void chainSensitiveMatchesPermittedSingleHop() {
        AuthorizationDecision decision = decide(authWithChain(List.of("zylos-gateway")), "/api/v1/hello/me");
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void chainSensitiveMatchesPermittedTwoHop() {
        AuthorizationDecision decision =
                decide(authWithChain(List.of("zylos-mobile-bff", "zylos-gateway")), "/api/v1/hello/me");
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void chainSensitiveMismatchIsDenied() {
        AuthorizationDecision decision = decide(authWithChain(List.of("zylos-internal-malicious")), "/api/v1/hello/me");
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void chainSensitiveEmptyChainIsDeniedWhenNotAllowed() {
        AuthorizationDecision decision = decide(authWithChain(List.of()), "/api/v1/hello/me");
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void chainSensitiveWildcardPathRespected() {
        AuthorizationDecision decision = decide(authWithChain(List.of("zylos-gateway")), "/api/v1/hello/seller/12345");
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void chainSensitiveDeeplyNestedChainRejectedByDepthGuard() {
        AuthorizationDecision decision =
                decide(authWithChain(List.of("a", "b", "c", "d", "e", "f", "g")), "/api/v1/hello/me");
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void nonSensitiveEndpointPermitsAnyAuthenticatedCallerWithoutChainMatch() {
        // The browse endpoint is chainSensitive=false. A caller whose chain
        // would NOT match any sensitive rule is still permitted, because the
        // chain is not consulted for non-sensitive endpoints.
        AuthorizationDecision decision =
                decide(authWithChain(List.of("some-unexpected-caller")), "/api/v1/hello/browse");
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void nonSensitiveEndpointDeniesUnauthenticatedRequest() {
        AuthorizationDecision decision = decide(() -> null, "/api/v1/hello/browse");
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void missingJwtOnChainSensitiveEndpointIsDenied() {
        AuthorizationDecision decision = decide(() -> null, "/api/v1/hello/me");
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void permitMetricIncrementsOnChainMatch() {
        decide(authWithChain(List.of("zylos-gateway")), "/api/v1/hello/me");
        assertThat(meterRegistry
                        .counter("zylos_actor_chain_decisions_total", "decision", "permit", "reason", "chain_match")
                        .count())
                .isEqualTo(1.0);
    }

    @Test
    void permitMetricIncrementsWithAuthenticatedReasonOnNonSensitive() {
        decide(authWithChain(List.of("anyone")), "/api/v1/hello/browse");
        assertThat(meterRegistry
                        .counter("zylos_actor_chain_decisions_total", "decision", "permit", "reason", "authenticated")
                        .count())
                .isEqualTo(1.0);
    }

    // --- helpers -----------------------------------------------------------

    private AuthorizationDecision decide(Supplier<Authentication> auth, String path) {
        HttpServletRequest request = new MockHttpServletRequest("GET", path);
        return manager.authorize(auth, new RequestAuthorizationContext(request));
    }
}
