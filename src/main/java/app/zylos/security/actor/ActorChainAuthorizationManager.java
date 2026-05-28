package app.zylos.security.actor;

import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Servlet-stack {@link AuthorizationManager} enforcing the Zylos actor-chain
 * policy per the authorization model (ADR 0003 refinement).
 *
 * <p>Resolves the request path against the {@link ActorChainEvaluator} and
 * dispatches on the {@link PathCheckResult}:
 * <ul>
 *   <li>{@link PathCheckResult.Immediate} — return the terminal decision
 *       without resolving the authentication.</li>
 *   <li>{@link PathCheckResult.AuthenticatedOnly} — permit if the request
 *       carries a valid token, deny otherwise.</li>
 *   <li>{@link PathCheckResult.ChainEvaluation} — extract and match the actor
 *       chain against the rule's permitted chains.</li>
 * </ul>
 */
public record ActorChainAuthorizationManager(ActorChainEvaluator evaluator)
        implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public @Nullable AuthorizationDecision authorize(
            Supplier<? extends Authentication> authentication, @Nullable RequestAuthorizationContext context) {

        if (context == null) {
            return new AuthorizationDecision(false);
        }

        HttpServletRequest request = context.getRequest();
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        String path = requestUri.startsWith(contextPath) ? requestUri.substring(contextPath.length()) : requestUri;

        return switch (evaluator.checkPath(path)) {
            case PathCheckResult.Immediate immediate -> immediate.decision();
            case PathCheckResult.AuthenticatedOnly ignored ->
                evaluator.evaluateAuthenticatedOnly(authentication.get(), path);
            case PathCheckResult.ChainEvaluation chainEval ->
                evaluator.evaluateToken(authentication.get(), path, chainEval.rule());
        };
    }
}
