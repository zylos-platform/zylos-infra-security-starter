package app.zylos.security.actor;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;

/**
 * Extracts an ordered chain of actors from a JWT's {@code act} claim.
 *
 * <p>Per RFC 8693, {@code act} is a JSON object that may nest a further
 * {@code act} object, expressing a delegation history. The outermost {@code
 * act} represents the most recent actor; the most deeply nested represents
 * the least recent. This extractor returns actors in <strong>chronological
 * order</strong> — least recent first, most recent last — to align with how
 * permitted-chains are written in {@code actor-chains.yaml}.
 *
 * <p>Consecutive duplicate actors (which can occur when the same client
 * performs multiple exchanges per the open OAuth) are collapsed into a single entry. This is consistent with the
 * architecture's view of chains as logical hops rather than literal
 * exchange steps.
 *
 * <p>Malformed {@code act} claims (e.g., not a JSON object) yield an empty
 * chain; this is reported as "no chain" to the {@link
 * ActorChainAuthorizationManager}, which then applies the configured
 * {@code allowEmptyChain} policy.
 *
 * <p>The {@code MAX_DEPTH} guard prevents stack abuse from pathologically
 * deep {@code act} nesting. Tokens exceeding the guard are extracted up to
 * the limit; the authorization manager's depth check (configured
 * separately) catches and rejects them.
 */
public final class ActChainExtractor {

    /**
     * Hard ceiling against malicious deeply-nested act claims.
     */
    static final int MAX_DEPTH = 20;

    private static final String ACT_CLAIM = "act";
    private static final String CLIENT_ID_FIELD = "client_id";
    private static final String SUB_FIELD = "sub";
    private static final Logger log = LoggerFactory.getLogger(ActChainExtractor.class);

    private ActChainExtractor() {
        // Utility class.
    }

    /**
     * Extract the delegation chain from a JWT in chronological order.
     *
     * @param jwt the validated JWT (must be non-null)
     * @return chronological actor list; empty if {@code act} is absent or
     * malformed; capped at {@link #MAX_DEPTH}
     */
    public static List<ActorPrincipal> extract(Jwt jwt) {
        Object actNode = jwt.getClaim(ACT_CLAIM);

        log.info("Extracting act chain from JWT with act claim: {}", actNode);

        if (actNode == null) {
            return List.of();
        }

        Deque<ActorPrincipal> outerToInner = new ArrayDeque<>();
        walk(actNode, outerToInner, 0);

        if (outerToInner.isEmpty()) {
            return List.of();
        }

        List<ActorPrincipal> chronological = new ArrayList<>(outerToInner).reversed();

        return collapseConsecutiveDuplicates(chronological);
    }

    @SuppressWarnings("unchecked")
    private static void walk(Object node, Deque<ActorPrincipal> accumulator, int depth) {
        if (depth >= MAX_DEPTH || !(node instanceof Map)) {
            return;
        }

        Map<String, Object> map = (Map<String, Object>) node;
        ActorPrincipal principal = new ActorPrincipal(asString(map.get(CLIENT_ID_FIELD)), asString(map.get(SUB_FIELD)));

        // Only add if at least one identifier is present.
        if (principal.clientId() != null || principal.sub() != null) {
            accumulator.addLast(principal);
        }

        Object nested = map.get(ACT_CLAIM);

        if (nested != null) {
            walk(nested, accumulator, depth + 1);
        }
    }

    private static java.lang.@Nullable String asString(@Nullable Object value) {
        return value instanceof String s ? s : null;
    }

    /**
     * Collapse consecutive duplicate actors. The same
     * {@link ActorPrincipal#matchKey} appearing twice in a row is treated as one
     * logical hop. Non-consecutive duplicates (e.g., A → B → A) are
     * preserved as distinct hops since they represent real delegation
     * round-trips.
     */
    private static List<ActorPrincipal> collapseConsecutiveDuplicates(List<ActorPrincipal> chain) {
        if (chain.size() < 2) {
            return chain;
        }

        List<ActorPrincipal> collapsed = new ArrayList<>(chain.size());
        ActorPrincipal previous = null;

        for (ActorPrincipal current : chain) {
            if (previous == null || !sameMatchKey(previous, current)) {
                collapsed.add(current);
            }

            previous = current;
        }

        return collapsed;
    }

    private static boolean sameMatchKey(ActorPrincipal a, ActorPrincipal b) {
        String left = a.matchKey();
        String right = b.matchKey();
        return left != null && left.equals(right);
    }
}
