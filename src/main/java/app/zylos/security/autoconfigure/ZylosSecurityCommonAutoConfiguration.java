package app.zylos.security.autoconfigure;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;

import com.github.benmanes.caffeine.cache.Caffeine;

import app.zylos.security.properties.ZylosSecurityProperties;

/**
 * Stack-agnostic beans for the Zylos security starter. This autoconfiguration
 * always activates when the starter is on the classpath; servlet- and
 * reactive-specific configurations layer on top of it.
 *
 * <p>Beans declared here:
 * <ul>
 *   <li>{@link ZylosSecurityProperties} — bound from {@code zylos.security.*}</li>
 *   <li>JWKS cache — a Caffeine-backed Spring {@link Cache} configured per
 *       properties; both servlet and reactive decoders share this exact instance
 *       so an unknown-kid refresh from one stack benefits the other if both
 *       happen to be present.</li>
 * </ul>
 */
@AutoConfiguration
@EnableConfigurationProperties(ZylosSecurityProperties.class)
public class ZylosSecurityCommonAutoConfiguration {

    /** Stable bean name; referenced explicitly by both decoder auto-configurations. */
    public static final String JWKS_CACHE_BEAN_NAME = "zylosJwksCache";

    @Bean(name = JWKS_CACHE_BEAN_NAME)
    @ConditionalOnMissingBean(name = JWKS_CACHE_BEAN_NAME)
    public Cache jwksCache(ZylosSecurityProperties properties) {
        long ttlMillis = Objects.requireNonNull(properties.jwksCache().ttl()).toMillis();
        int maxEntries = Objects.requireNonNull(properties.jwksCache().maxEntries());

        com.github.benmanes.caffeine.cache.Cache<Object, Object> caffeine = Caffeine.newBuilder()
                .expireAfterWrite(ttlMillis, TimeUnit.MILLISECONDS)
                .maximumSize(maxEntries)
                .recordStats()
                .build();
        return new CaffeineCache(JWKS_CACHE_BEAN_NAME, caffeine);
    }
}
