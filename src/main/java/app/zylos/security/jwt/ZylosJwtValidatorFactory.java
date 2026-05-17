package app.zylos.security.jwt;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;

import app.zylos.security.properties.ZylosSecurityProperties;

public final class ZylosJwtValidatorFactory {

    private ZylosJwtValidatorFactory() {
        // Utility class
    }

    public static OAuth2TokenValidator<Jwt> create(
            ZylosSecurityProperties properties, ObjectProvider<ZylosJwtValidatorCustomizer> customizers) {

        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();

        validators.add(new JwtTimestampValidator(properties.clockSkew()));
        validators.add(new JwtIssuerValidator(properties.issuerUri()));
        validators.add(new AudienceValidator(properties.expectedAudience()));

        customizers.orderedStream().forEach(customizer -> customizer.customize(validators));

        return new DelegatingOAuth2TokenValidator<>(validators);
    }
}
