package app.zylos.security.actor;

import jakarta.validation.constraints.Min;

/**
 * Defaults applied when no endpoint-specific rule matches a request, or as
 * cluster-wide constraints (e.g., max chain depth).
 *
 * @param rejectIfNoPathMatch when {@code true} (default) a request whose
 *                            path doesn't match any rule is denied; when {@code false} the request
 *                            is permitted (useful for services that only need chain validation on
 *                            a few endpoints)
 * @param allowEmptyChain     when {@code true} tokens without an {@code act}
 *                            claim are accepted (only relevant for direct user-to-service calls,
 *                            which are unusual in Zylos); default {@code false}
 * @param maxChainDepth       defense-in-depth ceiling on chain length; any chain
 *                            longer than this is rejected regardless of endpoint rules; default 5
 *                            per architecture
 */
public record ChainDefaults(
        boolean rejectIfNoPathMatch,
        boolean allowEmptyChain,
        @Min(1) int maxChainDepth) {

    /**
     * Conservative defaults used when not configured explicitly.
     */
    public static ChainDefaults strict() {
        return new ChainDefaults(true, false, 5);
    }
}
