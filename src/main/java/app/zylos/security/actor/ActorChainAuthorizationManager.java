package app.zylos.security.actor;

import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Servlet-stack {@link AuthorizationManager} enforcing the Zylos actor-chain
 * authorization policy per Phase 1 architecture §7.2.
 *
 * <p>Invoked after JWT authentication has populated the SecurityContext with
 * a validated {@link Jwt} principal. Looks up the configured chain rule for
 * the request path, extracts the {@code act} chain from the JWT, and
 * compares against permitted chains.
 *
 * <h2>Decision flow</h2>
 * <ol>
 *   <li>If the path matches a rule with {@code public: true}, permit.</li>
 *   <li>If the path matches no rule and {@code defaults.rejectIfNoPathMatch}
 *       is {@code true}, deny.</li>
 *   <li>If the extracted chain length exceeds {@code defaults.maxChainDepth},
 *       deny.</li>
 *   <li>If the chain is empty and {@code defaults.allowEmptyChain} is
 *       {@code false}, deny.</li>
 *   <li>If the chain matches any of the rule's {@code permittedChains},
 *       permit. Otherwise, deny.</li>
 * </ol>
 *
 * <p>Denials return an {@link AuthorityAuthorizationDecision} with the
 * required authority {@code ZYLOS_ACTOR_CHAIN_MATCH}, surfacing the failure
 * reason in standard Spring Security error-response handling.
 */
public record ActorChainAuthorizationManager(ActorChainEvaluator evaluator)
        implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public @Nullable AuthorizationDecision authorize(
            Supplier<? extends @Nullable Authentication> authentication,
            @Nullable RequestAuthorizationContext context) {

        if (context == null) {
            return new AuthorizationDecision(false);
        }

        HttpServletRequest request = context.getRequest();

        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        String path = requestUri.startsWith(contextPath) ? requestUri.substring(contextPath.length()) : requestUri;

        PathCheckResult check = evaluator.checkPath(path);

        if (!check.requiresAuthentication()) {
            return check.immediateDecision();
        }

        return evaluator.evaluateToken(authentication.get(), path, check.requiredRule());
    }
}
