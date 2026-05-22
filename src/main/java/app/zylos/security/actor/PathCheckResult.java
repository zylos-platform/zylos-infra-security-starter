package app.zylos.security.actor;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authorization.AuthorizationDecision;

public record PathCheckResult(
        @Nullable AuthorizationDecision immediateDecision,
        @Nullable EndpointChainRule requiredRule) {

    public boolean requiresAuthentication() {
        return immediateDecision == null;
    }
}
