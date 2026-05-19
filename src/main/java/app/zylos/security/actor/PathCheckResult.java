package app.zylos.security.actor;

import org.springframework.security.authorization.AuthorizationDecision;

public record PathCheckResult(
    AuthorizationDecision immediateDecision,
    EndpointChainRule requiredRule
) {
    public boolean requiresAuthentication() {
        return immediateDecision == null;
    }
}
