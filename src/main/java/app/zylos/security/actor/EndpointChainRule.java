package app.zylos.security.actor;

import java.util.List;
import java.util.Objects;

import jakarta.validation.constraints.NotBlank;

import org.jspecify.annotations.Nullable;

/**
 * Per-endpoint chain rule from {@code actor-chains.yaml}.
 *
 * @param pathPattern     Spring path-pattern syntax matching the request path
 *                        (e.g., {@code /api/v1/hello/me}, {@code /api/v1/hello/seller/**})
 * @param permittedChains list of permitted chains; each chain is a list of
 *                        client identifiers in chronological order (least-recent first); the
 *                        extracted chain matches if it is equal to any permitted chain by
 *                        {@link ActorPrincipal#matchKey}. Only consulted when {@code chainSensitive}
 *                        is {@code true}.
 * @param publicAccess    when {@code true} the endpoint skips authorization
 *                        entirely (the authorization manager permits the request); used for
 *                        unauthenticated routes
 * @param chainSensitive  when {@code true} the endpoint enforces actor-chain matching
 *                        against {@code permittedChains} (the hardened posture for
 *                        sensitive endpoints — payment, refund, admin, PII export). When
 *                        {@code false} (the default), the endpoint authorizes any caller with a
 *                        valid authenticated token; the chain is not matched. See ADR 0003's
 *                        refinement.
 */
public record EndpointChainRule(
        @NotBlank String pathPattern,
        @Nullable List<List<String>> permittedChains,
        boolean publicAccess,
        boolean chainSensitive) {

    /**
     * Compact canonical constructor: normalize a null permittedChains to an empty list.
     */
    public EndpointChainRule {
        if (permittedChains == null) {
            permittedChains = List.of();
        }
    }

    /**
     * Convenience constructor for non-chain-sensitive rules.
     * {@code chainSensitive} is {@code false}.
     *
     * <p>Retained so existing call sites (and tests) that predate the
     * {@code chainSensitive} flag compile unchanged.
     */
    public EndpointChainRule(String pathPattern, @Nullable List<List<String>> permittedChains, boolean publicAccess) {
        this(pathPattern, permittedChains, publicAccess, false);
    }

    @Override
    public List<List<String>> permittedChains() {
        return Objects.requireNonNull(permittedChains);
    }
}
