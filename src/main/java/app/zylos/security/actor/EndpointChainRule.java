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
 *                        {@link ActorPrincipal#matchKey}
 * @param publicAccess    when {@code true} the endpoint skips chain validation
 *                        entirely (the authorization manager permits the request); used for
 *                        unauthenticated routes
 */
public record EndpointChainRule(
        @NotBlank String pathPattern, @Nullable List<List<String>> permittedChains, boolean publicAccess) {

    public EndpointChainRule {
        if (permittedChains == null) {
            permittedChains = List.of();
        }
    }

    @Override
    public List<List<String>> permittedChains() {
        return Objects.requireNonNull(permittedChains);
    }
}
