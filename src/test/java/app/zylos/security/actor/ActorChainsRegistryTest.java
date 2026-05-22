package app.zylos.security.actor;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class ActorChainsRegistryTest {

    private static ActorChainsRegistry registryWith(EndpointChainRule... rules) {
        return new ActorChainsRegistry(new ActorChainsConfig(ChainDefaults.strict(), List.of(rules)));
    }

    private static EndpointChainRule rule(String pattern, List<List<String>> permitted) {
        return new EndpointChainRule(pattern, permitted, false);
    }

    @Test
    void emptyRegistryReturnsNoMatch() {
        ActorChainsRegistry registry = new ActorChainsRegistry(ActorChainsConfig.empty());

        Optional<EndpointChainRule> match = registry.findMatching("/api/v1/anything");

        assertThat(match).isEmpty();
        assertThat(registry.ruleCount()).isZero();
    }

    @Test
    void exactPathMatches() {
        ActorChainsRegistry registry = registryWith(rule("/api/v1/hello/me", List.of(List.of("zylos-gateway"))));

        Optional<EndpointChainRule> match = registry.findMatching("/api/v1/hello/me");

        assertThat(match).isPresent();
        assertThat(match.get().pathPattern()).isEqualTo("/api/v1/hello/me");
    }

    @Test
    void wildcardPathMatches() {
        ActorChainsRegistry registry = registryWith(rule("/api/v1/hello/seller/**", List.of(List.of("zylos-gateway"))));

        Optional<EndpointChainRule> match = registry.findMatching("/api/v1/hello/seller/12345");

        assertThat(match).isPresent();
    }

    @Test
    void firstRuleMatchesEvenIfMoreSpecificFollows() {
        // Documenting the "first match wins" semantics — ordering matters.
        ActorChainsRegistry registry = registryWith(
                rule("/api/v1/hello/**", List.of(List.of("zylos-gateway"))),
                rule("/api/v1/hello/me", List.of(List.of("specific-rule"))));

        Optional<EndpointChainRule> match = registry.findMatching("/api/v1/hello/me");

        assertThat(match).isPresent();
        assertThat(match.get().pathPattern()).isEqualTo("/api/v1/hello/**");
    }

    @Test
    void noMatchReturnsEmpty() {
        ActorChainsRegistry registry = registryWith(rule("/api/v1/known", List.of(List.of("zylos-gateway"))));

        Optional<EndpointChainRule> match = registry.findMatching("/api/v1/unknown");

        assertThat(match).isEmpty();
    }

    @Test
    void exposesDefaults() {
        ChainDefaults defaults = new ChainDefaults(false, true, 7);
        ActorChainsConfig config = new ActorChainsConfig(defaults, List.of());

        ActorChainsRegistry registry = new ActorChainsRegistry(config);

        assertThat(registry.defaults().rejectIfNoPathMatch()).isFalse();
        assertThat(registry.defaults().allowEmptyChain()).isTrue();
        assertThat(registry.defaults().maxChainDepth()).isEqualTo(7);
    }
}
