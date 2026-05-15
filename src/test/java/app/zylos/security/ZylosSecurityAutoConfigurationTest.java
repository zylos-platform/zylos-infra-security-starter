package app.zylos.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class ZylosSecurityAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ZylosSecurityAutoConfiguration.class));

    @Test
    void shouldLoadAutoConfiguration() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(ZylosSecurityAutoConfiguration.class);
        });
    }
}
