package app.zylos.security.actor;

import java.util.List;
import java.util.Optional;

import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * Indexed, query-optimized view of {@link ActorChainsConfig}.
 *
 * <p>Holds parsed {@link PathPattern} instances for each endpoint rule so
 * matching at request time is O(N) on the number of rules with native path
 * matching, rather than reparsing patterns per request.
 *
 * <p>Rules are evaluated in declaration order; the first match wins. Place
 * specific paths before broader patterns in {@code actor-chains.yaml}.
 *
 * <p>This registry is immutable post-construction.
 */
public final class ActorChainsRegistry {

    private final ChainDefaults defaults;
    private final List<CompiledRule> rules;

    public ActorChainsRegistry(ActorChainsConfig config) {
        this.defaults = config.defaults();
        PathPatternParser parser = PathPatternParser.defaultInstance;
        this.rules = config.endpoints().stream()
                .map(rule -> new CompiledRule(parser.parse(rule.pathPattern()), rule))
                .toList();
    }

    /**
     * Defaults section of the underlying config.
     */
    public ChainDefaults defaults() {
        return defaults;
    }

    /**
     * Look up the first rule whose pattern matches the given path.
     *
     * @param pathWithinApplication the request path stripped of any context
     *                              path (Spring's standard "path within application")
     * @return the first matching rule, or empty if none match
     */
    public Optional<EndpointChainRule> findMatching(String pathWithinApplication) {
        PathContainer container = PathContainer.parsePath(pathWithinApplication);

        for (CompiledRule rule : rules) {
            if (rule.pattern.matches(container)) {
                return Optional.of(rule.original);
            }
        }

        return Optional.empty();
    }

    /**
     * Total number of endpoint rules; exposed for diagnostics and metrics.
     */
    public int ruleCount() {
        return rules.size();
    }

    private record CompiledRule(PathPattern pattern, EndpointChainRule original) {}
}
