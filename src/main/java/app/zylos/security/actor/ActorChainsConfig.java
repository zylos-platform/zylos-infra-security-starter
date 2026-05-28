package app.zylos.security.actor;

import java.util.List;

import jakarta.validation.Valid;

import org.jspecify.annotations.Nullable;

/**
 * Root record of {@code actor-chains.yaml} — the full per-service chain
 * policy.
 *
 * @param defaults  defaults applied when no endpoint rule matches; never
 *                  {@code null} (the {@link ChainDefaults#standard()} is substituted
 * @param endpoints per-endpoint rules, evaluated in declaration order;
 *                  never {@code null} (defaults to empty list)
 */
public record ActorChainsConfig(
        @Nullable @Valid ChainDefaults defaults,
        @Nullable @Valid List<EndpointChainRule> endpoints) {

    public ActorChainsConfig {
        if (defaults == null) {
            defaults = ChainDefaults.standard();
        }

        if (endpoints == null) {
            endpoints = List.of();
        }
    }

    /**
     * Convenience for fully-default config (no endpoint rules; standard defaults).
     */
    public static ActorChainsConfig empty() {
        return new ActorChainsConfig(ChainDefaults.standard(), List.of());
    }
}
