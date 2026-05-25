package app.zylos.security.autoconfigure;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import com.github.benmanes.caffeine.cache.Caffeine;

import app.zylos.security.actor.ActorChainEvaluator;
import app.zylos.security.actor.ActorChainsConfig;
import app.zylos.security.actor.ActorChainsLoader;
import app.zylos.security.actor.ActorChainsRegistry;
import app.zylos.security.properties.ZylosSecurityProperties;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

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

    /**
     * Stable bean name; referenced explicitly by both decoder auto-configurations.
     */
    public static final String JWKS_CACHE_BEAN_NAME = "zylosJwksCache";

    @Bean(name = JWKS_CACHE_BEAN_NAME)
    @ConditionalOnMissingBean(name = JWKS_CACHE_BEAN_NAME)
    public Cache jwksCache(ZylosSecurityProperties properties) {
        long ttlMillis = Objects.requireNonNull(properties.jwksCache().ttl()).toMillis();
        long maxEntries = properties.jwksCache().maxEntries();

        com.github.benmanes.caffeine.cache.Cache<Object, Object> caffeine = Caffeine.newBuilder()
                .expireAfterWrite(ttlMillis, TimeUnit.MILLISECONDS)
                .maximumSize(maxEntries)
                .recordStats()
                .build();
        return new CaffeineCache(JWKS_CACHE_BEAN_NAME, caffeine);
    }

    @Bean
    @ConditionalOnMissingBean
    public MeterRegistry zylosSecurityFallbackMeterRegistry() {
        // Services should already provide a Micrometer registry; this is a fallback
        // so the starter doesn't break in tests / minimal setups.
        return new SimpleMeterRegistry();
    }

    /**
     * Loads {@code actor-chains.yaml} and exposes it as a registry. Active
     * only when {@code zylos.security.actor-chains.enabled=true} (the
     * default). Services without chain requirements should set the
     * property to {@code false}; failing to provide the file otherwise is
     * a fail-fast startup error.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
            prefix = "zylos.security.actor-chains",
            name = "enabled",
            havingValue = "true",
            matchIfMissing = true)
    public ActorChainsRegistry actorChainsRegistry(ZylosSecurityProperties properties, ResourceLoader resourceLoader)
            throws IOException {
        Resource resource = resourceLoader.getResource(properties.actorChains().location());
        ActorChainsConfig config = ActorChainsLoader.load(resource);
        return new ActorChainsRegistry(config);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ActorChainsRegistry.class)
    public ActorChainEvaluator actorChainEvaluator(ActorChainsRegistry registry, MeterRegistry meterRegistry) {
        return new ActorChainEvaluator(registry, meterRegistry);
    }

    /**
     * Bind Micrometer's Caffeine binder to the JWKS cache so hits, misses,
     * evictions, and load durations are exposed without any hand-rolled
     * counters. Uses the same standard binder the OPA decision cache uses.
     *
     * <p>The bean type is {@link MeterBinder} so Spring Boot's actuator
     * picks it up automatically when {@code micrometer-core} is present.
     */
    @Bean
    @ConditionalOnMissingBean(name = "jwksCacheMetricsBinder")
    public MeterBinder jwksCacheMetricsBinder(Cache jwksCache) {
        if (!(jwksCache instanceof CaffeineCache springCache)) {
            // The starter's default JWKS cache is a CaffeineCache; if a
            // consumer replaces the bean, we skip metrics binding rather
            // than fail.
            return _ -> {};
        }
        return registry -> CaffeineCacheMetrics.monitor(registry, springCache.getNativeCache(), "zylos_jwks_cache");
    }
}
