package app.zylos.security.jwt;

import java.util.List;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

@FunctionalInterface
public interface ZylosJwtValidatorCustomizer {

    /**
     * Customize the list of validators before they are wrapped in the delegator.
     *
     * @param validators the mutable list of current validators in the chain.
     */
    void customize(List<OAuth2TokenValidator<Jwt>> validators);
}
