package app.zylos.security.actor;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class ActChainExtractorTest {

    private static Map<String, Object> buildDeepActClaim() {
        int depth = ActChainExtractor.MAX_DEPTH + 10;
        Map<String, Object> current = Map.of("client_id", "level-" + (depth - 1));
        for (int i = depth - 2; i >= 0; i--) {
            current = Map.of("client_id", "level-" + i, "act", current);
        }
        return current;
    }

    private static Jwt jwt(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("test")
                .header("alg", "RS256")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300));
        claims.forEach(builder::claim);
        return builder.build();
    }

    @Test
    void emptyChainWhenActClaimIsAbsent() {
        Jwt jwt = jwt(Map.of("sub", "alice"));

        List<ActorPrincipal> chain = ActChainExtractor.extract(jwt);

        assertThat(chain).isEmpty();
    }

    @Test
    void singleHopChainExtractedCorrectly() {
        Jwt jwt = jwt(Map.of("sub", "alice", "act", Map.of("client_id", "zylos-gateway")));

        List<ActorPrincipal> chain = ActChainExtractor.extract(jwt);

        assertThat(chain).hasSize(1);
        assertThat(chain.getFirst().clientId()).isEqualTo("zylos-gateway");
    }

    @Test
    void twoHopChainExtractedInChronologicalOrder() {
        // act = current actor (zylos-internal-cart), nested act = prior actor (zylos-gateway)
        Jwt jwt = jwt(Map.of(
                "sub",
                "alice",
                "act",
                Map.of("client_id", "zylos-internal-cart", "act", Map.of("client_id", "zylos-gateway"))));

        List<ActorPrincipal> chain = ActChainExtractor.extract(jwt);

        assertThat(chain).extracting(ActorPrincipal::clientId).containsExactly("zylos-gateway", "zylos-internal-cart");
    }

    @Test
    void threeHopChainExtractedInChronologicalOrder() {
        // gateway → catalog → pricing → (this service)
        Jwt jwt = jwt(Map.of(
                "sub",
                "alice",
                "act",
                Map.of(
                        "client_id",
                        "zylos-internal-pricing",
                        "act",
                        Map.of("client_id", "zylos-internal-catalog", "act", Map.of("client_id", "zylos-gateway")))));

        List<ActorPrincipal> chain = ActChainExtractor.extract(jwt);

        assertThat(chain)
                .extracting(ActorPrincipal::clientId)
                .containsExactly("zylos-gateway", "zylos-internal-catalog", "zylos-internal-pricing");
    }

    @Test
    void falsBackToSubWhenClientIdIsMissing() {
        Jwt jwt = jwt(Map.of("sub", "alice", "act", Map.of("sub", "service-account-zylos-gateway")));

        List<ActorPrincipal> chain = ActChainExtractor.extract(jwt);

        assertThat(chain).hasSize(1);
        assertThat(chain.getFirst().clientId()).isNull();
        assertThat(chain.getFirst().sub()).isEqualTo("service-account-zylos-gateway");
        assertThat(chain.getFirst().matchKey()).isEqualTo("service-account-zylos-gateway");
    }

    @Test
    void prefersClientIdOverSubForMatchKey() {
        ActorPrincipal p = new ActorPrincipal("zylos-gateway", "service-account-zylos-gateway");

        assertThat(p.matchKey()).isEqualTo("zylos-gateway");
    }

    @Test
    void consecutiveDuplicatesAreCollapsed() {
        // produces nested duplicates. We collapse.
        Jwt jwt = jwt(Map.of(
                "sub",
                "alice",
                "act",
                Map.of("client_id", "zylos-gateway", "act", Map.of("client_id", "zylos-gateway"))));

        List<ActorPrincipal> chain = ActChainExtractor.extract(jwt);

        assertThat(chain).hasSize(1);
        assertThat(chain.getFirst().clientId()).isEqualTo("zylos-gateway");
    }

    @Test
    void nonConsecutiveDuplicatesArePreserved() {
        // A → B → A is a legitimate delegation cycle.
        Jwt jwt = jwt(Map.of(
                "sub",
                "alice",
                "act",
                Map.of(
                        "client_id",
                        "zylos-gateway",
                        "act",
                        Map.of("client_id", "zylos-internal-cart", "act", Map.of("client_id", "zylos-gateway")))));

        List<ActorPrincipal> chain = ActChainExtractor.extract(jwt);

        assertThat(chain)
                .extracting(ActorPrincipal::clientId)
                .containsExactly("zylos-gateway", "zylos-internal-cart", "zylos-gateway");
    }

    @Test
    void malformedActClaimYieldsEmptyChain() {
        // act is a string instead of an object.
        Jwt jwt = jwt(Map.of("sub", "alice", "act", "not-an-object"));

        List<ActorPrincipal> chain = ActChainExtractor.extract(jwt);

        assertThat(chain).isEmpty();
    }

    @Test
    void deeplyNestedActClaimIsCappedAtMaxDepth() {
        Map<String, Object> deepActClaim = buildDeepActClaim();
        Jwt jwt = jwt(Map.of("sub", "alice", "act", deepActClaim));

        List<ActorPrincipal> chain = ActChainExtractor.extract(jwt);

        assertThat(chain).hasSizeLessThanOrEqualTo(ActChainExtractor.MAX_DEPTH);
    }
}
