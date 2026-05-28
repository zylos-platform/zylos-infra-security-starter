package app.zylos.security.integration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.Tag;
import org.springframework.boot.test.context.SpringBootTest;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Composite annotation for the starter's integration tests.
 *
 * <p>Combines:
 * <ul>
 *   <li>{@link SpringBootTest} — bootstraps a full Spring context with the
 *       starter's auto-configurations active</li>
 *   <li>{@link Testcontainers} — manages the lifecycle of Docker containers
 *       declared with {@code @Container} (singleton pattern is preferred
 *       and implemented in {@link KeycloakIntegrationTestBase})</li>
 *   <li>{@link Tag} = "integration" — filterable from unit-test runs</li>
 * </ul>
 *
 * <p>Tests using this annotation run during the Maven {@code verify}
 * phase via the failsafe plugin, not the {@code test} phase via surefire.
 * The {@code *IT} class-name suffix is what failsafe picks up by default;
 * this annotation supplies the test-context configuration.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@SpringBootTest
@Testcontainers
@Tag("integration")
public @interface IntegrationTest {}
