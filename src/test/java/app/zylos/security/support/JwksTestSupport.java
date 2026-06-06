package app.zylos.security.support;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Generates an RSA key, serves its public JWK set, and mints RS256 tokens for decoder tests.
 */
public final class JwksTestSupport {

    private final RSAKey rsaKey;

    public JwksTestSupport() {
        try {
            this.rsaKey = new RSAKeyGenerator(2048).keyID("test-key-1").generate();
        } catch (Exception e) {
            throw new IllegalStateException("key gen failed", e);
        }
    }

    public String jwksJson() {
        return new JWKSet(rsaKey.toPublicJWK()).toString();
    }

    public String mint(String issuer, String audience) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .audience(List.of(audience))
                    .subject("test-subject")
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
                    .build();
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(rsaKey.getKeyID())
                            .build(),
                    claims);
            jwt.sign(new RSASSASigner(rsaKey.toPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("mint failed", e);
        }
    }
}
