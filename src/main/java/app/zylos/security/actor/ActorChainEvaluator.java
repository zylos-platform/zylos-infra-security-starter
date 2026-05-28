package app.zylos.security.actor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Stack-agnostic actor-chain decision logic shared by the servlet and reactive
 * authorization managers.
 *
 * <h2>Decision flow</h2>
 *
 * <p>{@link #checkPath} resolves the path against the registry and returns one
 * of three {@link PathCheckResult} cases:
 * <ol>
 *   <li>Path matches a {@code publicAccess} rule → {@code Immediate(permit)}.</li>
 *   <li>Path matches no rule:
 *     <ul>
 *       <li>{@code rejectIfNoPathMatch == true} (strict) → {@code Immediate(deny)}.</li>
 *       <li>{@code rejectIfNoPathMatch == false} (standard) →
 *           {@code AuthenticatedOnly}.</li>
 *     </ul>
 *   </li>
 *   <li>Path matches a rule:
 *     <ul>
 *       <li>{@code chainSensitive == false} (default) → {@code AuthenticatedOnly}.</li>
 *       <li>{@code chainSensitive == true} → {@code ChainEvaluation(rule)}.</li>
 *     </ul>
 *   </li>
 * </ol>
 *
 * <p>{@link #evaluateAuthenticatedOnly} permits when a valid JWT is present and
 * denies otherwise. {@link #evaluateToken} performs the full chain match for
 * chain-sensitive endpoints (depth guard, empty-chain policy, permitted-chain
 * comparison).
 */
public final class ActorChainEvaluator {

    private static final Logger log = LoggerFactory.getLogger(ActorChainEvaluator.class);

    private static final String REQUIRED_AUTHORITY = "ZYLOS_ACTOR_CHAIN_MATCH";
    private static final String METRIC_NAME = "zylos_actor_chain_decisions_total";

    private final ActorChainsRegistry registry;
    private final MeterRegistry meterRegistry;

    private final Map<String, Counter> permitCounters = new ConcurrentHashMap<>();
    private final Map<String, Counter> denyCounters = new ConcurrentHashMap<>();

    public ActorChainEvaluator(ActorChainsRegistry registry, MeterRegistry meterRegistry) {
        this.registry = registry;
        this.meterRegistry = meterRegistry;
    }

    private static @Nullable Jwt extractJwt(@Nullable Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken token) return token.getToken();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) return jwt;
        return null;
    }

    private static boolean chainMatches(List<ActorPrincipal> actual, List<List<String>> permitted) {
        List<String> actualKeys = new ArrayList<>(actual.size());
        for (ActorPrincipal principal : actual) {
            String key = principal.matchKey();
            if (key == null) {
                return false;
            }
            actualKeys.add(key);
        }
        for (List<String> permittedChain : permitted) {
            if (actualKeys.equals(permittedChain)) return true;
        }
        return false;
    }

    /**
     * Path-only phase. See class-level decision flow. Public-access and strict
     * no-match decisions are terminal (counter incremented here); the
     * authenticated-only and chain-evaluation cases defer the counter increment
     * to {@link #evaluateAuthenticatedOnly} / {@link #evaluateToken}.
     */
    public PathCheckResult checkPath(String path) {
        Optional<EndpointChainRule> ruleOpt = registry.findMatching(path);

        if (ruleOpt.isPresent() && ruleOpt.get().publicAccess()) {
            return new PathCheckResult.Immediate(permit(path, "public"));
        }

        if (ruleOpt.isEmpty()) {
            if (registry.defaults().rejectIfNoPathMatch()) {
                return new PathCheckResult.Immediate(deny(path, "no_matching_rule"));
            }
            // standard: an unlisted path permits an authenticated caller.
            return new PathCheckResult.AuthenticatedOnly();
        }

        EndpointChainRule rule = ruleOpt.get();
        if (!rule.chainSensitive()) {
            // Non-sensitive endpoint: a valid token is sufficient; no chain match.
            return new PathCheckResult.AuthenticatedOnly();
        }

        // Chain-sensitive: defer to evaluateToken with the matched rule.
        return new PathCheckResult.ChainEvaluation(rule);
    }

    /**
     * Authenticated-only authorization: permit when a valid JWT is present,
     * deny otherwise. Used for non-chain-sensitive endpoints and (under
     * standard defaults) unmatched paths.
     */
    public AuthorizationDecision evaluateAuthenticatedOnly(@Nullable Authentication authentication, String path) {
        if (authentication == null || extractJwt(authentication) == null) {
            return deny(path, "no_jwt");
        }
        return permit(path, "authenticated");
    }

    /**
     * Full chain evaluation for a chain-sensitive endpoint: depth guard,
     * empty-chain policy, and permitted-chain comparison.
     */
    public AuthorizationDecision evaluateToken(
            @Nullable Authentication authentication, String path, EndpointChainRule rule) {
        if (authentication == null) {
            return deny(path, "no_jwt");
        }
        Jwt jwt = extractJwt(authentication);
        if (jwt == null) {
            return deny(path, "no_jwt");
        }

        List<ActorPrincipal> chain = ActChainExtractor.extract(jwt);

        if (chain.size() > registry.defaults().maxChainDepth()) {
            return deny(path, "chain_too_deep");
        }
        if (chain.isEmpty() && !registry.defaults().allowEmptyChain()) {
            return deny(path, "empty_chain");
        }
        if (chainMatches(chain, rule.permittedChains())) {
            return permit(path, "chain_match");
        }
        return deny(path, "chain_mismatch");
    }

    private AuthorizationDecision permit(String path, String reason) {
        permitCounters
                .computeIfAbsent(reason, r -> meterRegistry.counter(METRIC_NAME, "decision", "permit", "reason", r))
                .increment();
        if (log.isDebugEnabled()) {
            log.debug("Actor chain check permitted for path={} reason={}", path, reason);
        }
        return new AuthorizationDecision(true);
    }

    private AuthorizationDecision deny(String path, String reason) {
        denyCounters
                .computeIfAbsent(reason, r -> meterRegistry.counter(METRIC_NAME, "decision", "deny", "reason", r))
                .increment();
        log.info("Actor chain check denied for path={} reason={}", path, reason);
        return new AuthorityAuthorizationDecision(false, List.of(new SimpleGrantedAuthority(REQUIRED_AUTHORITY)));
    }
}
