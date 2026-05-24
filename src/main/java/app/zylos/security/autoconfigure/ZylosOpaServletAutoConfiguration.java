package app.zylos.security.autoconfigure;

import java.net.URI;
import java.util.Objects;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestClient;

import app.zylos.security.opa.CachingOpaClient;
import app.zylos.security.opa.OpaClient;
import app.zylos.security.opa.RestClientOpaClient;
import app.zylos.security.properties.ZylosSecurityProperties;

import io.micrometer.core.instrument.MeterRegistry;

@AutoConfiguration(after = ZylosSecurityCommonAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(RestClient.class)
@ConditionalOnProperty(prefix = "zylos.security.opa", name = "endpoint")
public class ZylosOpaServletAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(OpaClient.class)
    public OpaClient opaClient(ZylosSecurityProperties properties, MeterRegistry meterRegistry) {

        ZylosSecurityProperties.OpaProperties opa = properties.opa();
        URI endpoint =
                Objects.requireNonNull(opa.endpoint(), "zylos.security.opa.endpoint is required when OPA is enabled");

        OpaClient backend =
                RestClientOpaClient.create(endpoint, opa.connectTimeout(), opa.readTimeout(), meterRegistry);
        return new CachingOpaClient(backend, opa.cacheTtl(), opa.cacheMaxSize(), meterRegistry);
    }
}
