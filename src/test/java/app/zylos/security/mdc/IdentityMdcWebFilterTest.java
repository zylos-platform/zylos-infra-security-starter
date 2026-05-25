package app.zylos.security.mdc;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.server.WebFilterChain;

import app.zylos.security.properties.ZylosSecurityProperties;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class IdentityMdcWebFilterTest {

    private final IdentityMdcWebFilter filter =
            new IdentityMdcWebFilter(new ZylosSecurityProperties.MdcProperties(true, "X-Correlation-Id"));

    @Test
    void writesCorrelationIdToReactorContextWhenHeaderAbsent() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test"));

        WebFilterChain chain = _ -> Mono.deferContextual(ctx -> {
            assertThat((String) ctx.get(MdcKeys.CORRELATION_ID)).isNotBlank();
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getHeaders().getFirst("X-Correlation-Id"))
                .isNotBlank();
    }

    @Test
    void preservesIncomingCorrelationIdInContextAndResponseHeader() {
        MockServerWebExchange exchange =
                MockServerWebExchange.from(MockServerHttpRequest.get("/test").header("X-Correlation-Id", "trace-xyz"));

        WebFilterChain chain = _ -> Mono.deferContextual(ctx -> {
            assertThat((String) ctx.get(MdcKeys.CORRELATION_ID)).isEqualTo("trace-xyz");
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getHeaders().getFirst("X-Correlation-Id"))
                .isEqualTo("trace-xyz");
    }

    @Test
    void writesSubjectToContextWhenAuthenticated() {
        MockServerWebExchange exchange =
                MockServerWebExchange.from(MockServerHttpRequest.get("/test").header("X-Correlation-Id", "trace-1"));

        SecurityContextImpl securityContext =
                new SecurityContextImpl(new TestingAuthenticationToken("alice", "cred", "ROLE_USER"));

        WebFilterChain chain = _ -> Mono.deferContextual(ctx -> {
            assertThat(ctx.getOrDefault(MdcKeys.SUBJECT, "")).isEqualTo("alice");
            return Mono.empty();
        });

        Mono<Void> filtered = filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));

        StepVerifier.create(filtered).verifyComplete();
    }

    @Test
    void doesNotWriteSubjectWhenUnauthenticated() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test"));

        WebFilterChain chain = _ -> Mono.deferContextual(ctx -> {
            assertThat(ctx.getOrDefault(MdcKeys.SUBJECT, "absent")).isEqualTo("absent");
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
    }
}
