package app.zylos.security.actor;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class ActorChainEvaluatorTest {

    // --- helpers -----------------------------------------------------------

    private static ActorChainEvaluator evaluator(ChainDefaults defaults, EndpointChainRule... rules) {
        ActorChainsConfig config = new ActorChainsConfig(defaults, List.of(rules));
        return new ActorChainEvaluator(new ActorChainsRegistry(config), new SimpleMeterRegistry());
    }

    private static Authentication jwtAuth(List<String> chain) {
        Object actClaim = null;
        for (String actor : chain) {
            actClaim = actClaim == null ? Map.of("client_id", actor) : Map.of("client_id", actor, "act", actClaim);
        }
        Jwt.Builder builder = Jwt.withTokenValue("test")
                .header("alg", "RS256")
                .subject("alice")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300));
        if (actClaim != null) {
            builder.claim("act", actClaim);
        }
        return new JwtAuthenticationToken(builder.build(), List.of());
    }

    @Test
    void publicPathYieldsImmediatePermit() {
        ActorChainEvaluator evaluator =
                evaluator(ChainDefaults.standard(), new EndpointChainRule("/public", List.of(), true, false));

        PathCheckResult result = evaluator.checkPath("/public");

        assertThat(result).isInstanceOf(PathCheckResult.Immediate.class);
        assertThat(((PathCheckResult.Immediate) result).decision().isGranted()).isTrue();
    }

    @Test
    void unmatchedPathUnderStandardDefaultsIsAuthenticatedOnly() {
        ActorChainEvaluator evaluator = evaluator(ChainDefaults.standard());

        PathCheckResult result = evaluator.checkPath("/anything");

        assertThat(result).isInstanceOf(PathCheckResult.AuthenticatedOnly.class);
    }

    @Test
    void unmatchedPathUnderStrictDefaultsIsImmediateDeny() {
        ActorChainEvaluator evaluator = evaluator(ChainDefaults.strict());

        PathCheckResult result = evaluator.checkPath("/anything");

        assertThat(result).isInstanceOf(PathCheckResult.Immediate.class);
        assertThat(((PathCheckResult.Immediate) result).decision().isGranted()).isFalse();
    }

    @Test
    void nonSensitiveRuleIsAuthenticatedOnly() {
        ActorChainEvaluator evaluator =
                evaluator(ChainDefaults.standard(), new EndpointChainRule("/cart", List.of(), false, false));

        PathCheckResult result = evaluator.checkPath("/cart");

        assertThat(result).isInstanceOf(PathCheckResult.AuthenticatedOnly.class);
    }

    @Test
    void sensitiveRuleIsChainEvaluation() {
        ActorChainEvaluator evaluator = evaluator(
                ChainDefaults.standard(),
                new EndpointChainRule("/payments", List.of(List.of("zylos-gateway")), false, true));

        PathCheckResult result = evaluator.checkPath("/payments");

        assertThat(result).isInstanceOf(PathCheckResult.ChainEvaluation.class);
        assertThat(((PathCheckResult.ChainEvaluation) result).rule().pathPattern())
                .isEqualTo("/payments");
    }

    @Test
    void evaluateAuthenticatedOnlyPermitsWithValidJwt() {
        ActorChainEvaluator evaluator = evaluator(ChainDefaults.standard());

        AuthorizationDecision decision = evaluator.evaluateAuthenticatedOnly(jwtAuth(List.of()), "/cart");

        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void evaluateAuthenticatedOnlyDeniesWithoutAuthentication() {
        ActorChainEvaluator evaluator = evaluator(ChainDefaults.standard());

        AuthorizationDecision decision = evaluator.evaluateAuthenticatedOnly(null, "/cart");

        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void evaluateTokenMatchesChainForSensitiveRule() {
        EndpointChainRule rule = new EndpointChainRule("/payments", List.of(List.of("zylos-gateway")), false, true);
        ActorChainEvaluator evaluator = evaluator(ChainDefaults.standard(), rule);

        AuthorizationDecision decision = evaluator.evaluateToken(jwtAuth(List.of("zylos-gateway")), "/payments", rule);

        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void evaluateTokenDeniesMismatchedChain() {
        EndpointChainRule rule = new EndpointChainRule("/payments", List.of(List.of("zylos-gateway")), false, true);
        ActorChainEvaluator evaluator = evaluator(ChainDefaults.standard(), rule);

        AuthorizationDecision decision =
                evaluator.evaluateToken(jwtAuth(List.of("zylos-internal-cart")), "/payments", rule);

        assertThat(decision.isGranted()).isFalse();
    }
}
