package app.zylos.security.autoconfigure;

import java.net.URI;
import java.util.Objects;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.function.client.WebClient;

import app.zylos.security.opa.ReactiveCachingOpaClient;
import app.zylos.security.opa.ReactiveOpaClient;
import app.zylos.security.opa.WebClientOpaClient;
import app.zylos.security.properties.ZylosSecurityProperties;

import io.micrometer.core.instrument.MeterRegistry;

@AutoConfiguration(after = ZylosSecurityCommonAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass(WebClient.class)
@ConditionalOnProperty(prefix = "zylos.security.opa", name = "endpoint")
public class ZylosOpaReactiveAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(ReactiveOpaClient.class)
    public ReactiveOpaClient reactiveOpaClient(ZylosSecurityProperties properties, MeterRegistry meterRegistry) {

        ZylosSecurityProperties.OpaProperties opa = properties.opa();
        URI endpoint =
                Objects.requireNonNull(opa.endpoint(), "zylos.security.opa.endpoint is required when OPA is enabled");

        ReactiveOpaClient backend =
                WebClientOpaClient.create(endpoint, opa.connectTimeout(), opa.readTimeout(), meterRegistry);
        return new ReactiveCachingOpaClient(backend, opa.cacheTtl(), opa.cacheMaxSize(), meterRegistry);
    }
}
