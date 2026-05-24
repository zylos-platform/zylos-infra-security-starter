package app.zylos.security.opa;

import reactor.core.publisher.Mono;

public interface ReactiveOpaClient {

    <T> Mono<T> evaluate(String policyPath, Object input, Class<T> resultType);

    default Mono<Boolean> check(String policyPath, Object input) {
        return evaluate(policyPath, input, OpaDecisionResponse.class)
                .map(response -> Boolean.TRUE.equals(response.allow()))
                .defaultIfEmpty(false)
                .onErrorReturn(false);
    }
}
