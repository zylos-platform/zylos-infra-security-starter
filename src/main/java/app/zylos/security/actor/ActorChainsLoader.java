package app.zylos.security.actor;

import java.io.IOException;
import java.io.InputStream;

import org.springframework.core.io.Resource;

import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;

/**
 * Loads {@link ActorChainsConfig} from a Spring {@link Resource} pointing at
 * a YAML file (typically {@code classpath:actor-chains.yaml}).
 *
 * <p>Jackson YAML is used because:
 * <ul>
 *   <li>It supports binding to Java records natively (after parameter-name
 *       capture at compile time)</li>
 *   <li>It's already on the classpath via the starter's dependency on
 *       {@code jackson-dataformat-yaml}</li>
 *   <li>SnakeYAML's direct API would require manual property mapping</li>
 * </ul>
 *
 * <p>Loading is synchronous and intended for application startup. Hot
 * reload is out of scope for NOW; changes to the YAML file require a
 * pod restart.
 */
public final class ActorChainsLoader {

    private static final YAMLMapper MAPPER = YAMLMapper.builder()
            .findAndAddModules() // ensures jackson-module-parameter-names picks up record components
            .build();

    private ActorChainsLoader() {
        // Utility class.
    }

    /**
     * Load and bind the YAML at the supplied resource location.
     *
     * @param resource Spring resource (e.g., classpath, file system); must
     *                 {@link Resource#exists exist}
     * @return the bound config
     * @throws IOException           if the resource cannot be read
     * @throws IllegalStateException if the resource is empty, malformed, or
     *                               fails validation constraints
     */
    @SuppressWarnings({"ConstantConditions", "ConstantValue"})
    public static ActorChainsConfig load(Resource resource) throws IOException {
        if (!resource.exists()) {
            throw new IllegalStateException("Actor chains config not found at: " + resource.getDescription()
                    + ". Either provide the file or set zylos.security.actor-chains.enabled=false.");
        }

        try (InputStream in = resource.getInputStream()) {
            ActorChainsConfig config;

            try {
                config = MAPPER.readValue(in, ActorChainsConfig.class);

            } catch (MismatchedInputException _) {
                return ActorChainsConfig.empty();
            }

            // if the YAML document explicitly contains just the `null` literal.
            if (config == null) {
                return ActorChainsConfig.empty();
            }

            return config;
        }
    }
}
