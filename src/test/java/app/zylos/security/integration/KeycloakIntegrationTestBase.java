package app.zylos.security.integration;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.slf4j.LoggerFactory;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.output.Slf4jLogConsumer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import dasniko.testcontainers.keycloak.KeycloakContainer;

/**
 * Base class for the starter's Keycloak-backed integration tests.
 *
 * <p>Implements the <strong>singleton container pattern</strong> from the
 * Testcontainers documentation: a single {@link KeycloakContainer} is
 * created in a {@code static} initializer and reused across every test
 * class that extends this base. The container lives for the entire test
 * JVM, amortizing the ~10s startup cost across all integration tests.
 *
 * <p>The container imports {@code /keycloak/zylos-test-realm.json} on startup,
 * providing a fully-formed test realm with clients, roles, and users —
 * eliminating per-test setup of identity-provider state.
 *
 * <p>Subclasses inherit:
 * <ul>
 *   <li>The Keycloak container (started, healthy, ready for use)</li>
 *   <li>Spring properties (issuer URI) wired via {@link DynamicPropertySource}</li>
 *   <li>{@link #obtainToken} helper for client-credentials grant</li>
 *   <li>{@link #exchangeToken} helper for RFC 8693 token exchange (to produce
 *       tokens with {@code act} claims for actor-chain testing)</li>
 * </ul>
 *
 * <p>Image is pinned to match the realm-config-cli compatibility shown in
 * the realm import file: Keycloak 26.6.1.
 */
public abstract class KeycloakIntegrationTestBase {

    /**
     * Test-realm identifier (matches realm.json).
     */
    protected static final String TEST_REALM = "zylos-test";

    /**
     * Test-realm client identifiers (must align with zylos-test-realm.json).
     */
    protected static final String CLIENT_GATEWAY = "zylos-gateway";

    protected static final String CLIENT_INTERNAL_TEST = "zylos-internal-test";
    protected static final String CLIENT_INTERNAL_CALLER = "zylos-internal-caller";
    protected static final String CLIENT_ROGUE_CALLER = "zylos-rogue-caller";

    /**
     * Test-realm client secrets (dev-only; in realm.json).
     */
    protected static final String SECRET_GATEWAY = "dev-secret-gateway";

    protected static final String SECRET_INTERNAL_TEST = "dev-secret-internal-test";
    protected static final String SECRET_INTERNAL_CALLER = "dev-secret-internal-caller";
    protected static final String SECRET_ROGUE_CALLER = "dev-secret-rogue-caller";

    /**
     * Single shared container across the entire test JVM.
     */
    protected static final KeycloakContainer KEYCLOAK = new KeycloakContainer("quay.io/keycloak/keycloak:26.6.1")
            .withRealmImportFile("keycloak/zylos-test-realm.json")
            .withStartupTimeout(Duration.ofMinutes(2))
            .withReuse(false) // Disabled for CI; can be enabled locally for speed
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("KeycloakContainer")));

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    static {
        KEYCLOAK.start();
    }

    /**
     * Issuer URI wired into the Spring context.
     */
    @DynamicPropertySource
    static void keycloakProperties(DynamicPropertyRegistry registry) {
        registry.add("zylos.security.issuer-uri", () -> KEYCLOAK.getAuthServerUrl() + "/realms/" + TEST_REALM);
        // Each test class can override expected-audience via its own @DynamicPropertySource
        // or @TestPropertySource; default matches the resource-server client.
        registry.add("zylos.security.expected-audience", () -> CLIENT_INTERNAL_TEST);
    }

    /**
     * Token endpoint for the test realm.
     */
    protected static URI tokenEndpoint() {
        return URI.create(KEYCLOAK.getAuthServerUrl() + "/realms/" + TEST_REALM + "/protocol/openid-connect/token");
    }

    /**
     * Obtain an access token via {@code client_credentials} grant.
     *
     * @param clientId     the requesting client's clientId
     * @param clientSecret the client's confidential secret
     * @return JWT access token (compact serialization)
     */
    protected static String obtainToken(String clientId, String clientSecret) throws IOException, InterruptedException {
        String form = "grant_type=client_credentials" + "&client_id=" + clientId + "&client_secret=" + clientSecret;
        HttpRequest request = HttpRequest.newBuilder(tokenEndpoint())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException("Token request failed: " + response.statusCode() + " " + response.body());
        }

        JsonNode body = MAPPER.readTree(response.body());
        return body.get("access_token").asText();
    }

    /**
     * Perform RFC 8693 standard token exchange.
     *
     * <p>The requesting client exchanges its existing access token for a
     * new token bound to {@code targetAudience}. The resulting token's
     * {@code act} claim records the requesting client as the actor —
     * exactly the shape consumed by the actor-chain validator.
     *
     * @param requestingClient       confidential client requesting the exchange
     *                               (must have {@code oauth2.token.exchange.grant.enabled: true} in
     *                               the realm)
     * @param requestingClientSecret the requesting client's secret
     * @param subjectToken           the existing access token to exchange
     * @param targetAudience         the audience the new token will be bound to
     * @return the exchanged token (with {@code act} claim populated)
     */
    protected static String exchangeToken(
            String requestingClient, String requestingClientSecret, String subjectToken, String targetAudience)
            throws IOException, InterruptedException {

        String tokenType = "urn:ietf:params:oauth:token-type:access_token";
        String grantType = "urn:ietf:params:oauth:grant-type:token-exchange";
        String actorToken = obtainToken(requestingClient, requestingClientSecret);

        String form = "grant_type=" + grantType
                + "&client_id=" + requestingClient
                + "&client_secret=" + requestingClientSecret
                + "&subject_token=" + subjectToken
                + "&subject_token_type=" + tokenType
                + "&actor_token=" + actorToken
                + "&actor_token_type=" + tokenType
                + "&audience=" + targetAudience;

        HttpRequest request = HttpRequest.newBuilder(tokenEndpoint())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException("Token exchange failed: " + response.statusCode() + " " + response.body());
        }

        JsonNode body = MAPPER.readTree(response.body());
        return body.get("access_token").asText();
    }
}
