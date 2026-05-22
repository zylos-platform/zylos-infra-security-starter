package app.zylos.security.actor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

class ActorChainsLoaderTest {

    @Test
    void loadsValidConfigFromClasspath() throws Exception {
        ActorChainsConfig config = ActorChainsLoader.load(new ClassPathResource("test-actor-chains/valid.yaml"));

        assertThat(config.defaults().rejectIfNoPathMatch()).isTrue();
        assertThat(config.defaults().allowEmptyChain()).isFalse();
        assertThat(config.defaults().maxChainDepth()).isEqualTo(5);
        assertThat(config.endpoints()).hasSize(3);

        EndpointChainRule first = config.endpoints().getFirst();
        assertThat(first.pathPattern()).isEqualTo("/api/v1/hello/public");
        assertThat(first.publicAccess()).isTrue();

        EndpointChainRule second = config.endpoints().get(1);
        assertThat(second.pathPattern()).isEqualTo("/api/v1/hello/me");
        assertThat(second.permittedChains()).hasSize(2);
        assertThat(second.permittedChains().getFirst()).containsExactly("zylos-gateway");
    }

    @Test
    void loadsMinimalConfigUsingDefaults() throws Exception {
        ActorChainsConfig config = ActorChainsLoader.load(new ClassPathResource("test-actor-chains/minimal.yaml"));

        assertThat(config.endpoints()).isEmpty();
        assertThat(config.defaults().maxChainDepth()).isEqualTo(5);
    }

    @Test
    void throwsOnMissingResource() {
        ClassPathResource missing = new ClassPathResource("does-not-exist.yaml");

        assertThatThrownBy(() -> ActorChainsLoader.load(missing))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Actor chains config not found");
    }
}
