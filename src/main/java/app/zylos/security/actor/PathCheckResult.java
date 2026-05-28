package app.zylos.security.actor;

import org.springframework.security.authorization.AuthorizationDecision;

/**
 * Outcome of the path-only phase of actor-chain evaluation
 * ({@link ActorChainEvaluator#checkPath}). A sealed sum type with three
 * cases, reflecting the authorization model:
 *
 * <ul>
 *   <li>{@link Immediate} — a decision reached without inspecting the token
 *       (public-access permit, or strict no-match deny). The authorization
 *       manager returns it directly without resolving the authentication.</li>
 *   <li>{@link AuthenticatedOnly} — the path requires a valid authenticated
 *       token but no chain matching. This covers non-chain-sensitive endpoints
 *       (the default) and unmatched paths under {@code standard}
 *       defaults. Permit if a JWT is present; deny otherwise.</li>
 *   <li>{@link ChainEvaluation} — the path is chain-sensitive; the actor
 *       chain must be extracted and matched against the rule's permitted
 *       chains.</li>
 * </ul>
 *
 * <p>Splitting the path check from token evaluation lets the reactive
 * authorization manager skip resolving the authentication {@code Mono} for
 * the {@link Immediate} case.
 */
public sealed interface PathCheckResult {

    /**
     * Terminal decision requiring no token inspection.
     */
    record Immediate(AuthorizationDecision decision) implements PathCheckResult {}

    /**
     * Requires a valid authenticated token; no chain matching.
     */
    record AuthenticatedOnly() implements PathCheckResult {}

    /**
     * Requires token extraction and chain matching against the rule.
     */
    record ChainEvaluation(EndpointChainRule rule) implements PathCheckResult {}
}
