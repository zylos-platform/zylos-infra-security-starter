package app.zylos.security.actor;

import org.jspecify.annotations.Nullable;

/**
 * Identity of a single actor in a delegation chain extracted from a JWT's
 * {@code act} claim.
 *
 * <p>RFC 8693 specifies that {@code act} contains claims identifying the
 * actor, with the exact field set being implementation-defined. Keycloak's
 * standard token exchange populates {@code client_id} (the requesting
 * client's identifier) and {@code sub} (the service account user's subject).
 *
 * <p>For Zylos chain matching, {@code clientId} is the primary identity
 * (matches our {@code zylos-*} client identifiers); {@code sub} is retained
 * for diagnostics and as a fallback when {@code client_id} is absent.
 *
 * @param clientId the {@code client_id} field from this {@code act} entry,
 *                 or {@code null} if absent
 * @param sub      the {@code sub} field from this {@code act} entry, or
 *                 {@code null} if absent
 */
public record ActorPrincipal(@Nullable String clientId, @Nullable String sub) {

    /**
     * The canonical identifier used for matching. Prefers {@code clientId}
     * over {@code sub} since chain-matching policies are written in
     * client-id terms.
     *
     * @return the client_id if present, else the sub, else {@code null}
     */
    public @Nullable String matchKey() {
        return clientId != null ? clientId : sub;
    }
}
