package app.zylos.security.actor;

import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

/**
 * Reactive-stack equivalent of {@link ActorChainAuthorizationManager}.
 *
 * <p>Implements the same five-step decision flow. The reactive
 * {@link AuthorizationContext} provides the {@code ServerWebExchange} from
 * which the request path is read.
 */
public record ActorChainReactiveAuthorizationManager(
    ActorChainEvaluator evaluator
) implements ReactiveAuthorizationManager<AuthorizationContext> {

    @Override
    public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, AuthorizationContext context) {
        String path = context.getExchange().getRequest().getPath().pathWithinApplication().value();

        PathCheckResult check = evaluator.checkPath(path);

        if (!check.requiresAuthentication()) {
            return Mono.just(check.immediateDecision());
        }

        return authentication
            .<AuthorizationResult>map(auth -> evaluator.evaluateToken(auth, path, check.requiredRule()))
            .defaultIfEmpty(evaluator.denyFallback(path));
    }
}
