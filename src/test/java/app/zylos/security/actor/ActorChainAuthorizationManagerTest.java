package app.zylos.security.actor;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class ActorChainAuthorizationManagerTest {

    private ActorChainAuthorizationManager manager;
    private MeterRegistry meterRegistry;

    private static Authentication authWithChain(List<String> chain) {
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
        return new JwtAuthenticationToken(builder.build(), List.of());
    }

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        ActorChainsConfig config = new ActorChainsConfig(
                ChainDefaults.strict(),
                List.of(
                        new EndpointChainRule("/api/v1/hello/public", List.of(), true),
                        new EndpointChainRule(
                                "/api/v1/hello/me",
                                List.of(List.of("zylos-gateway"), List.of("zylos-mobile-bff", "zylos-gateway")),
                                false),
                        new EndpointChainRule("/api/v1/hello/seller/**", List.of(List.of("zylos-gateway")), false)));

        ActorChainEvaluator evaluator = new ActorChainEvaluator(new ActorChainsRegistry(config), meterRegistry);
        manager = new ActorChainAuthorizationManager(evaluator);
    }

    /**
     * Helper to mock the Spring Security 7 context and simulate a mounted context path.
     */
    private AuthorizationResult check(Authentication auth, String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest();

        // Simulating an enterprise deployment where the app is mounted behind a context path
        request.setContextPath("/zylos-api");
        request.setRequestURI("/zylos-api" + uri);

        RequestAuthorizationContext context = new RequestAuthorizationContext(request);

        return manager.authorize(() -> auth, context);
    }

    @Test
    void publicEndpointIsPermittedRegardlessOfChain() {
        AuthorizationResult result = check(authWithChain(List.of()), "/api/v1/hello/public");
        assertThat(result.isGranted()).isTrue();
    }

    @Test
    void noMatchingPathIsDeniedByDefault() {
        AuthorizationResult result = check(authWithChain(List.of("zylos-gateway")), "/api/v1/unknown");
        assertThat(result.isGranted()).isFalse();
    }

    @Test
    void chainMatchesPermittedSingleHop() {
        AuthorizationResult result = check(authWithChain(List.of("zylos-gateway")), "/api/v1/hello/me");
        assertThat(result.isGranted()).isTrue();
    }

    @Test
    void chainMatchesPermittedTwoHop() {
        AuthorizationResult result =
                check(authWithChain(List.of("zylos-mobile-bff", "zylos-gateway")), "/api/v1/hello/me");
        assertThat(result.isGranted()).isTrue();
    }

    @Test
    void chainMismatchIsDenied() {
        AuthorizationResult result = check(authWithChain(List.of("zylos-internal-malicious")), "/api/v1/hello/me");
        assertThat(result.isGranted()).isFalse();
    }

    @Test
    void emptyChainIsDeniedWhenNotAllowed() {
        AuthorizationResult result = check(authWithChain(List.of()), "/api/v1/hello/me");
        assertThat(result.isGranted()).isFalse();
    }

    @Test
    void wildcardPathRespectedForSellerRoute() {
        AuthorizationResult result = check(authWithChain(List.of("zylos-gateway")), "/api/v1/hello/seller/12345");
        assertThat(result.isGranted()).isTrue();
    }

    @Test
    void deeplyNestedChainIsRejectedByDepthGuard() {
        AuthorizationResult result =
                check(authWithChain(List.of("a", "b", "c", "d", "e", "f", "g")), "/api/v1/hello/me");
        assertThat(result.isGranted()).isFalse();
    }

    @Test
    void missingJwtAuthenticationIsDenied() {
        AuthorizationResult result = check(null, "/api/v1/hello/me");
        assertThat(result.isGranted()).isFalse();
    }

    @Test
    void permitMetricIncrementsOnSuccess() {
        check(authWithChain(List.of("zylos-gateway")), "/api/v1/hello/me");

        double count = meterRegistry
                .find("zylos_actor_chain_decisions_total")
                .tag("decision", "permit")
                .counter()
                .count();
        assertThat(count).isEqualTo(1.0);
    }

    @Test
    void denyMetricIncrementsOnFailure() {
        check(authWithChain(List.of("wrong-actor")), "/api/v1/hello/me");

        double count = meterRegistry
                .find("zylos_actor_chain_decisions_total")
                .tag("decision", "deny")
                .counter()
                .count();
        assertThat(count).isGreaterThan(0.0);
    }
}
