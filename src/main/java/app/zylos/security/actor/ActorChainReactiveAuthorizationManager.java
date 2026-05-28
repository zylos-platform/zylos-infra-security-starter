package app.zylos.security.actor;

import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;

import reactor.core.publisher.Mono;

/**
 * Reactive-stack equivalent of {@link ActorChainAuthorizationManager}.
 *
 * <p>Dispatches on the same three {@link PathCheckResult} cases. The
 * {@link PathCheckResult.Immediate} case returns without subscribing to the
 * authentication {@code Mono}; the other two resolve it (defaulting to a
 * {@code null} authentication when the context carries none, so the evaluator
 * can deny with reason {@code no_jwt}).
 */
public record ActorChainReactiveAuthorizationManager(ActorChainEvaluator evaluator)
        implements ReactiveAuthorizationManager<AuthorizationContext> {

    @Override
    public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, AuthorizationContext context) {

        String path = context.getExchange()
                .getRequest()
                .getPath()
                .pathWithinApplication()
                .value();

        return switch (evaluator.checkPath(path)) {
            case PathCheckResult.Immediate immediate -> Mono.just(immediate.decision());
            case PathCheckResult.AuthenticatedOnly ignored ->
                authentication
                        .<AuthorizationResult>map(auth -> evaluator.evaluateAuthenticatedOnly(auth, path))
                        .switchIfEmpty(Mono.fromSupplier(() -> evaluator.evaluateAuthenticatedOnly(null, path)));
            case PathCheckResult.ChainEvaluation chainEval ->
                authentication
                        .<AuthorizationResult>map(auth -> evaluator.evaluateToken(auth, path, chainEval.rule()))
                        .switchIfEmpty(Mono.fromSupplier(() -> evaluator.evaluateToken(null, path, chainEval.rule())));
        };
    }
}
