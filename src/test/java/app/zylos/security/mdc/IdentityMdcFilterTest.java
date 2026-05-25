package app.zylos.security.mdc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.UUID;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import app.zylos.security.properties.ZylosSecurityProperties;

class IdentityMdcFilterTest {

    private IdentityMdcFilter filter;

    @BeforeEach
    void setUp() {
        filter = new IdentityMdcFilter(new ZylosSecurityProperties.MdcProperties(true, "X-Correlation-Id"));
    }

    @AfterEach
    void clearMdc() {
        MDC.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void generatesCorrelationIdWhenHeaderAbsent() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        String correlationId = response.getHeader("X-Correlation-Id");
        assertThat(correlationId).isNotBlank();
        assertThat(UUID.fromString(correlationId)).isNotNull(); // valid UUID format
    }

    @Test
    void preservesIncomingCorrelationId() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Correlation-Id", "abc-123");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getHeader("X-Correlation-Id")).isEqualTo("abc-123");
    }

    @Test
    void mdcIsPopulatedDuringChainExecution() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Correlation-Id", "trace-abc");
        MockHttpServletResponse response = new MockHttpServletResponse();

        String[] capturedCorrelation = new String[1];
        String[] capturedSubject = new String[1];

        FilterChain chain = (_, _) -> {
            capturedCorrelation[0] = MDC.get(MdcKeys.CORRELATION_ID);
            capturedSubject[0] = MDC.get(MdcKeys.SUBJECT);
        };

        filter.doFilter(request, response, chain);

        assertThat(capturedCorrelation[0]).isEqualTo("trace-abc");
        assertThat(capturedSubject[0]).isNull(); // no authentication set
    }

    @Test
    void mdcIncludesSubjectWhenAuthenticated() throws ServletException, IOException {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(new TestingAuthenticationToken("alice", "credentials", "ROLE_USER"));
        SecurityContextHolder.setContext(securityContext);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        String[] capturedSubject = new String[1];
        FilterChain chain = (_, _) -> capturedSubject[0] = MDC.get(MdcKeys.SUBJECT);

        filter.doFilter(request, response, chain);

        assertThat(capturedSubject[0]).isEqualTo("alice");
    }

    @Test
    void mdcIsClearedAfterRequest() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(MDC.get(MdcKeys.CORRELATION_ID)).isNull();
        assertThat(MDC.get(MdcKeys.SUBJECT)).isNull();
    }

    @Test
    void mdcIsClearedEvenWhenChainThrows() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain throwingChain = (_, _) -> {
            throw new ServletException("boom");
        };

        try {
            filter.doFilter(request, response, throwingChain);
        } catch (Exception _) {
            // expected
        }

        assertThat(MDC.get(MdcKeys.CORRELATION_ID)).isNull();
        assertThat(MDC.get(MdcKeys.SUBJECT)).isNull();
    }
}
